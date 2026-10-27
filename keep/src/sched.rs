//! The scheduler: which task runs next.
//!
//! Round robin over a fixed table of tasks. The Keep allocates nothing
//! after boot, so the table and every task's kernel stack are set aside
//! up front. The timer interrupts the running task every tick and the
//! next ready task gets the CPU, so a task that never yields still can't
//! keep the others from running.
//!
//! A task is either the Keep's own (ring 0, sharing the Keep's address
//! space) or a user program (ring 3, in an address space of its own that
//! shares the Keep's higher half). On every switch the scheduler points
//! the CPU at the next task's address space and kernel stack, so a user
//! task traps back onto its own kernel stack.
//!
//! Slot 0 is the idle task: the boot thread, which becomes it once boot
//! is done. It runs only when no other task is ready, and never sleeps
//! or exits.

#![forbid(unsafe_code)]

use crate::arch::layout::{TASK_SLOTS, stack_top};
use crate::arch::sync::Exclusive;
use crate::arch::task::Context;
use crate::arch::{cpu, gdt, paging};
use crate::user::Program;
use abi::Error;

pub const MAX_TASKS: usize = TASK_SLOTS;
const IDLE: usize = 0;
/// Writs a task may hold at once.
pub const CAPS_PER_TASK: usize = 8;
/// Endpoints the Keep sets aside at boot.
pub const MAX_ENDPOINTS: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Ready,
    Running,
    /// Waiting for the clock to reach this tick.
    Sleeping(u64),
    /// Blocked sending to, or receiving from, this endpoint.
    BlockedSend(usize),
    BlockedRecv(usize),
    Exited,
}

/// How a task ended.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Called exit with this code.
    Exited(u64),
    /// Was ended by the Keep after a fault.
    Faulted,
}

/// A Writ: an unforgeable right the Keep placed in a task's capability
/// table. A task names one by its index there and can't make one up.
#[derive(Clone, Copy)]
pub enum Writ {
    /// The right to send to and/or receive from an endpoint. A message
    /// sent through it is stamped with `badge`, so the receiver learns
    /// which sender it came from.
    Endpoint {
        endpoint: usize,
        send: bool,
        recv: bool,
        badge: u64,
    },
    /// The right to ask after another task (watch it).
    Task { slot: usize },
    /// The right to drive a device: I/O ports `[base, base + count)`. The
    /// Keep's microkernel keeps drivers in ring 3, so a driver task holds
    /// one of these for exactly its device's registers and nothing else.
    Io { base: u16, count: u16 },
}

/// A FIFO of tasks waiting on an endpoint, linked through `Task::wait_next`
/// so it needs no memory of its own.
#[derive(Clone, Copy)]
struct Waiters {
    head: Option<usize>,
    tail: Option<usize>,
}

impl Waiters {
    const EMPTY: Waiters = Waiters {
        head: None,
        tail: None,
    };
}

/// An endpoint: where senders and receivers meet. One of the two queues
/// is always empty — a waiter means no partner was ready.
#[derive(Clone, Copy)]
struct Endpoint {
    senders: Waiters,
    receivers: Waiters,
}

struct Task {
    name: &'static str,
    state: State,
    /// The top-level page table to load for this task (its CR3).
    space_root: u64,
    /// The saved registers, while the task is ready, sleeping or blocked.
    context: Option<Context>,
    /// The Writs this task holds.
    caps: [Option<Writ>; CAPS_PER_TASK],
    /// The badge to stamp on a message, while blocked sending.
    badge_out: u64,
    /// The next task in an endpoint's wait queue.
    wait_next: Option<usize>,
    /// How it ended, once it has.
    outcome: Option<Outcome>,
    /// Timer ticks that found this task running.
    ticks: u64,
}

struct Scheduler {
    tasks: [Option<Task>; MAX_TASKS],
    endpoints: [Endpoint; MAX_ENDPOINTS],
    current: usize,
    /// The address space now loaded, so a switch to the same one is free.
    current_root: u64,
    /// Ticks since the timer started.
    now: u64,
}

static SCHEDULER: Exclusive<Scheduler> = Exclusive::new(Scheduler::new());

impl Scheduler {
    const fn new() -> Scheduler {
        let mut tasks = [const { None }; MAX_TASKS];
        tasks[IDLE] = Some(Task {
            name: "idle",
            state: State::Running,
            space_root: 0,
            context: None,
            caps: [None; CAPS_PER_TASK],
            badge_out: 0,
            wait_next: None,
            outcome: None,
            ticks: 0,
        });
        Scheduler {
            tasks,
            endpoints: [Endpoint {
                senders: Waiters::EMPTY,
                receivers: Waiters::EMPTY,
            }; MAX_ENDPOINTS],
            current: IDLE,
            current_root: 0,
            now: 0,
        }
    }

    fn task(&mut self, slot: usize) -> Option<&mut Task> {
        self.tasks.get_mut(slot).and_then(Option::as_mut)
    }

    /// A Writ the task in `slot` holds at `handle`, if any.
    fn cap(&mut self, slot: usize, handle: u64) -> Option<Writ> {
        let handle = usize::try_from(handle).ok()?;
        self.task(slot)?.caps.get(handle).copied().flatten()
    }

    /// Add `slot` to the back of a wait queue, linked through `wait_next`.
    fn enqueue(&mut self, queue: Waiters, slot: usize) -> Waiters {
        if let Some(task) = self.task(slot) {
            task.wait_next = None;
        }
        match queue.tail {
            None => Waiters {
                head: Some(slot),
                tail: Some(slot),
            },
            Some(prev) => {
                if let Some(task) = self.task(prev) {
                    task.wait_next = Some(slot);
                }
                Waiters {
                    head: queue.head,
                    tail: Some(slot),
                }
            }
        }
    }

    /// Take the task at the front of a wait queue.
    fn dequeue(&mut self, queue: Waiters) -> (Waiters, Option<usize>) {
        let Some(head) = queue.head else {
            return (queue, None);
        };
        let next = self.task(head).and_then(|t| t.wait_next);
        let rest = match next {
            None => Waiters::EMPTY,
            Some(_) => Waiters {
                head: next,
                tail: queue.tail,
            },
        };
        (rest, Some(head))
    }

    /// Save the interrupted task's registers and pick the next task,
    /// pointing the CPU at its address space and kernel stack.
    fn reschedule(&mut self, interrupted: Context, tick: bool) -> Context {
        if tick {
            self.now = self.now.wrapping_add(1);
            let now = self.now;
            if let Some(task) = self.task(self.current) {
                task.ticks = task.ticks.wrapping_add(1);
            }
            for task in self.tasks.iter_mut().flatten() {
                if let State::Sleeping(until) = task.state
                    && until <= now
                {
                    task.state = State::Ready;
                }
            }
        }

        let Some(task) = self.task(self.current) else {
            return interrupted; // the running task always has a slot
        };
        match task.state {
            State::Running => {
                task.state = State::Ready;
                task.context = Some(interrupted);
            }
            State::Exited => {} // never resumed, so its registers go
            // Ready, sleeping or blocked: keep its registers to resume.
            State::Ready | State::Sleeping(_) | State::BlockedSend(_) | State::BlockedRecv(_) => {
                task.context = Some(interrupted)
            }
        }

        let next = self.next_after(self.current);
        self.current = next;
        self.apply_space(next);
        let resume = self.task(next).and_then(|task| {
            task.state = State::Running;
            task.context.take()
        });
        match resume {
            Some(context) => context,
            // Every task that isn't running has saved registers.
            None => crate::fail_closed(),
        }
    }

    /// Point the CPU at task `slot`'s address space (if it changed) and,
    /// for a real task, its kernel stack, so a ring-3 trap lands there.
    fn apply_space(&mut self, slot: usize) {
        let Some(root) = self.task(slot).map(|t| t.space_root) else {
            return;
        };
        if root != 0 && root != self.current_root {
            paging::activate(root);
            self.current_root = root;
        }
        if slot != IDLE {
            gdt::set_kernel_stack(stack_top(slot));
        }
    }

    /// The first ready task after `slot`, in slot order, or the idle task
    /// if none is ready.
    fn next_after(&self, slot: usize) -> usize {
        (1..=MAX_TASKS)
            .map(|step| (slot + step) % MAX_TASKS)
            .filter(|&i| i != IDLE)
            .find(|&i| matches!(self.tasks.get(i), Some(Some(task)) if task.state == State::Ready))
            .unwrap_or(IDLE)
    }

    /// Send a message through the endpoint a send Writ at `handle` names:
    /// hand it to a waiting receiver and keep running, or block until one
    /// arrives. The message words are in the sender's own frame.
    fn send(&mut self, handle: u64, current: Context) -> Context {
        let cur = self.current;
        let Some(Writ::Endpoint {
            endpoint,
            send: true,
            badge,
            ..
        }) = self.cap(cur, handle)
        else {
            current.set_result(Error::BadCapability.to_raw());
            return current;
        };
        if endpoint >= MAX_ENDPOINTS {
            current.set_result(Error::BadCapability.to_raw());
            return current;
        }
        let (rest, receiver) = self.dequeue(self.endpoints[endpoint].receivers);
        self.endpoints[endpoint].receivers = rest;
        if let Some(recv_slot) = receiver {
            let words = current.message();
            if let Some(task) = self.task(recv_slot) {
                if let Some(ctx) = task.context.as_ref() {
                    ctx.deliver(badge, words);
                }
                task.state = State::Ready;
            }
            current.set_result(0);
            current
        } else {
            if let Some(task) = self.task(cur) {
                task.state = State::BlockedSend(endpoint);
                task.badge_out = badge;
            }
            let queue = self.enqueue(self.endpoints[endpoint].senders, cur);
            self.endpoints[endpoint].senders = queue;
            self.reschedule(current, false)
        }
    }

    /// Receive a message through the endpoint a receive Writ at `handle`
    /// names: take a waiting sender's message, or block until one sends.
    fn recv(&mut self, handle: u64, current: Context) -> Context {
        let cur = self.current;
        let Some(Writ::Endpoint {
            endpoint,
            recv: true,
            ..
        }) = self.cap(cur, handle)
        else {
            current.set_result(Error::BadCapability.to_raw());
            return current;
        };
        if endpoint >= MAX_ENDPOINTS {
            current.set_result(Error::BadCapability.to_raw());
            return current;
        }
        let (rest, sender) = self.dequeue(self.endpoints[endpoint].senders);
        self.endpoints[endpoint].senders = rest;
        if let Some(send_slot) = sender {
            let mut words = [0u64; 4];
            let mut badge = 0;
            if let Some(task) = self.task(send_slot) {
                if let Some(ctx) = task.context.as_ref() {
                    words = ctx.message();
                    ctx.set_result(0);
                }
                badge = task.badge_out;
                task.state = State::Ready;
            }
            current.deliver(badge, words);
            current
        } else {
            if let Some(task) = self.task(cur) {
                task.state = State::BlockedRecv(endpoint);
            }
            let queue = self.enqueue(self.endpoints[endpoint].receivers, cur);
            self.endpoints[endpoint].receivers = queue;
            self.reschedule(current, false)
        }
    }

    /// Report the status of the task a Task Writ at `handle` names.
    fn watch(&mut self, handle: u64, current: Context) -> Context {
        let Some(Writ::Task { slot }) = self.cap(self.current, handle) else {
            current.set_result(Error::BadCapability.to_raw());
            return current;
        };
        let status = match self.task(slot) {
            Some(task) => match (task.state, task.outcome) {
                (State::Exited, Some(Outcome::Exited(code))) => {
                    abi::status::encode(abi::status::EXITED, code)
                }
                (State::Exited, _) => abi::status::encode(abi::status::FAULTED, 0),
                _ => abi::status::ALIVE,
            },
            None => abi::status::encode(abi::status::EXITED, 0),
        };
        current.set_result(status);
        current
    }
}

/// Record the Keep's own address space, which the idle task and every
/// kernel task run in. Call once, at boot, after the Keep's tables load.
pub fn set_kernel_space(root: u64) {
    SCHEDULER.with(|s| {
        s.current_root = root;
        if let Some(idle) = s.task(IDLE) {
            idle.space_root = root;
        }
    });
}

/// Start a kernel task running `entry(arg)` in the Keep's address space.
/// Returns its slot, or None if every slot is taken.
pub fn spawn(name: &'static str, entry: extern "C" fn(u64) -> !, arg: u64) -> Option<usize> {
    SCHEDULER
        .with(|s| {
            let root = s.task(IDLE)?.space_root;
            let slot = s.tasks.iter().position(Option::is_none)?;
            let context = Context::new_kernel(slot, entry, arg)?;
            place(s, slot, name, root, context, &[]);
            Some(slot)
        })
        .flatten()
}

/// Start a user task from a loaded `program`, passing it `arg` and seeding
/// its capability table with `caps`. Returns its slot, or None if every
/// slot is taken.
pub fn spawn_user(name: &'static str, program: &Program, arg: u64, caps: &[Writ]) -> Option<usize> {
    SCHEDULER
        .with(|s| {
            let slot = s.tasks.iter().position(Option::is_none)?;
            let context = Context::new_user(slot, program.entry, program.stack_top, arg)?;
            place(s, slot, name, program.space.root(), context, caps);
            Some(slot)
        })
        .flatten()
}

/// Place a Writ in task `slot`'s capability table at `handle`. The Keep
/// does this at boot; a task can't grant itself a Writ.
pub fn grant(slot: usize, handle: usize, writ: Writ) {
    SCHEDULER.with(|s| {
        if let Some(task) = s.task(slot)
            && let Some(cell) = task.caps.get_mut(handle)
        {
            *cell = Some(writ);
        }
    });
}

fn place(
    s: &mut Scheduler,
    slot: usize,
    name: &'static str,
    root: u64,
    context: Context,
    caps: &[Writ],
) {
    let mut table = [None; CAPS_PER_TASK];
    for (cell, writ) in table.iter_mut().zip(caps) {
        *cell = Some(*writ);
    }
    if let Some(task) = s.tasks.get_mut(slot) {
        *task = Some(Task {
            name,
            state: State::Ready,
            space_root: root,
            context: Some(context),
            caps: table,
            badge_out: 0,
            wait_next: None,
            outcome: None,
            ticks: 0,
        });
    }
}

/// The timer interrupted the running task. Returns the task to resume.
pub fn tick(interrupted: Context) -> Context {
    reschedule(interrupted, true)
}

/// The running task gave up the CPU. Returns the task to resume.
pub fn switch(interrupted: Context) -> Context {
    reschedule(interrupted, false)
}

/// Send through an endpoint. Returns the task to resume.
pub fn send(handle: u64, current: Context) -> Context {
    match SCHEDULER.with(|s| s.send(handle, current)) {
        Some(next) => next,
        None => crate::fail_closed(),
    }
}

/// Receive from an endpoint. Returns the task to resume.
pub fn recv(handle: u64, current: Context) -> Context {
    match SCHEDULER.with(|s| s.recv(handle, current)) {
        Some(next) => next,
        None => crate::fail_closed(),
    }
}

/// Report a watched task's status into the caller's result.
pub fn watch(handle: u64, current: Context) -> Context {
    match SCHEDULER.with(|s| s.watch(handle, current)) {
        Some(next) => next,
        None => crate::fail_closed(),
    }
}

/// Whether the running task holds an I/O Writ at `handle` whose port range
/// covers `port`: the check behind every device-I/O system call.
pub fn io_allows(handle: u64, port: u16) -> bool {
    SCHEDULER
        .with(|s| {
            let cur = s.current;
            matches!(
                s.cap(cur, handle),
                Some(Writ::Io { base, count })
                    if port >= base && u32::from(port) < u32::from(base) + u32::from(count)
            )
        })
        .unwrap_or(false)
}

/// End the running user task, which faulted, and run the next task. The
/// caller has already logged the fault.
pub fn kill_current(interrupted: Context) -> Context {
    finish(Outcome::Faulted);
    reschedule(interrupted, false)
}

/// A user task called sleep: wait at least `ticks` ticks, then run the
/// next task. The task resumes where it left off.
pub fn sleep_current(ticks: u64, interrupted: Context) -> Context {
    SCHEDULER.with(|s| {
        let now = s.now;
        if s.current != IDLE
            && let Some(task) = s.task(s.current)
        {
            task.state = State::Sleeping(now.saturating_add(ticks));
        }
    });
    reschedule(interrupted, false)
}

/// A user task called exit: end it with `code`, then run the next task.
pub fn exit_current(code: u64, interrupted: Context) -> Context {
    finish(Outcome::Exited(code));
    reschedule(interrupted, false)
}

/// Mark the running task ended with `outcome`, unless it is the idle task.
fn finish(outcome: Outcome) {
    SCHEDULER.with(|s| {
        let current = s.current;
        if current != IDLE
            && let Some(task) = s.task(current)
        {
            task.state = State::Exited;
            task.outcome = Some(outcome);
        }
    });
}

fn reschedule(interrupted: Context, tick: bool) -> Context {
    match SCHEDULER.with(|s| s.reschedule(interrupted, tick)) {
        Some(next) => next,
        // Only a trap inside the scheduler itself can get here.
        None => crate::fail_closed(),
    }
}

/// Become the idle task: boot is over, and from here on the boot thread
/// only waits for interrupts while the scheduler runs everything else.
pub fn become_idle() -> ! {
    loop {
        cpu::wait_for_interrupt();
    }
}

/// Timer ticks since the timer started.
pub fn now() -> u64 {
    SCHEDULER.with(|s| s.now).unwrap_or(0)
}

/// How a task ended, or None if it is still alive or has no slot.
pub fn outcome(slot: usize) -> Option<Outcome> {
    SCHEDULER
        .with(|s| s.task(slot).and_then(|t| t.outcome))
        .flatten()
}

/// Whether the task in `slot` is alive (started and not yet ended).
pub fn is_alive(slot: usize) -> bool {
    SCHEDULER
        .with(|s| matches!(s.task(slot).map(|t| t.state), Some(state) if state != State::Exited))
        .unwrap_or(false)
}

/// The running task's slot and name, unless it is the idle task (which is
/// the boot thread until boot is done). None also when called from inside
/// the scheduler, as a trap there would be.
pub fn running_task() -> Option<(usize, &'static str)> {
    SCHEDULER
        .with(|s| {
            let current = s.current;
            let name = s.task(current)?.name;
            (current != IDLE).then_some((current, name))
        })
        .flatten()
}
