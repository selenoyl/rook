//! The Keep: Rook's microkernel.
//!
//! Boot: `arch::boot` brings the CPU into 64-bit mode in the higher half
//! and calls `keep_main`, which moves the legacy interrupt controllers
//! out of the way, installs the GDT and IDT, checks that traps come back,
//! replaces the boot page tables with the Keep's own, loads the first
//! user programs, raises the walls between ring 0 and ring 3, and starts
//! the timer. Then the boot thread becomes the idle task and the
//! scheduler runs everything: Michael the supervisor, and the ring-3 test
//! program. Message passing and Writs come next.

#![no_std]
#![no_main]

#[macro_use]
mod log;

// The only module allowed to use `unsafe`; see UNSAFE.md.
#[allow(unsafe_code)]
mod arch;

mod banner;
mod bootinfo;
mod frames;
mod memory;
mod programs;
mod sched;
mod syscall;
mod trap;
mod user;

use bootinfo::BootInfo;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use frames::{Frames, Range};
use sched::{Outcome, Writ};

/// The two endpoints the Keep sets aside to connect the supervisor and
/// the task it watches: one for requests, one for replies.
const REQUEST_EP: usize = 0;
const REPLY_EP: usize = 1;

/// The primary ATA bus's I/O ports (0x1F0..0x1F8), which the Vault's I/O
/// Writ covers so the storage service can drive the disk from ring 3.
const ATA_IO_BASE: u16 = 0x1F0;
const ATA_IO_COUNT: u16 = 8;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Memory below 1 MiB belongs to the BIOS and devices.
const LOW_MEMORY: u64 = 1 << 20;
/// The boot identity map reaches this far, so boot allocations stay
/// below it.
const BOOT_MAP_LIMIT: u64 = 1 << 30;

/// The scheduler's tick.
const TICK_MS: u32 = 10;
const TICKS_PER_SECOND: u64 = 1000 / TICK_MS as u64;

/// Set by `selftest` on the kernel command line: report the result to
/// QEMU and exit instead of idling.
static SELFTEST: AtomicBool = AtomicBool::new(false);

/// Set if every check the Keep makes of itself before starting user mode
/// passed.
static BOOT_OK: AtomicBool = AtomicBool::new(false);

/// A `ret` instruction in writable data, for the no-execute test.
static NX_PROBE: AtomicU8 = AtomicU8::new(0xC3);

/// What the ring-3 test program should do, and so what counts as success.
#[derive(Clone, Copy)]
enum Watch {
    /// Run its checks and exit with 0.
    Checks,
    /// Crash on purpose; the Keep should end it and keep Michael running.
    Crash,
}

/// Called by `arch::boot` once the CPU is in 64-bit mode, with the serial
/// log working and the boot loader's information copied out.
pub fn keep_main(multiboot: bool, boot: BootInfo) -> ! {
    kprintln!("[keep] Rook Keep v{VERSION} starting");
    if !multiboot {
        kprintln!("[keep] boot: not started by a Multiboot loader; stopping");
        fail_closed();
    }
    SELFTEST.store(boot.has_word("selftest"), Ordering::Relaxed);
    kprintln!("[keep] boot: command line \"{}\"", boot.cmdline());
    log_memory_map(&boot);

    let long_mode = arch::cpu::long_mode_active();
    let nx = arch::cpu::nx_enabled();
    kprintln!(
        "[keep] cpu: long mode {}, no-execute {}",
        on_off(long_mode),
        on_off(nx)
    );

    arch::pic::disable();
    arch::gdt::init();
    kprintln!("[keep] gdt: ring-0 and ring-3 segments, TSS and double-fault stack ready");
    arch::idt::init();
    kprintln!("[keep] idt: 32 exception gates, plus timer, yield, syscall and spurious");

    let check_ok = self_check();
    kprintln!(
        "[keep] self-check: {}",
        if check_ok { "passed" } else { "FAILED" }
    );

    let apic = match arch::apic::phys_base() {
        Ok(base) => base,
        Err(e) => {
            kprintln!("[keep] timer: {e}; stopping");
            fail_closed();
        }
    };
    let booted = setup_memory(&boot, apic);
    let tick_counts = setup_timer();

    let walls = arch::cpu::harden();
    kprintln!(
        "[keep] walls: no-user-execute {}, no-user-access {}, hide-tables {}; floating-point off",
        on_off(walls.no_user_execute),
        on_off(walls.no_user_access),
        on_off(walls.hide_tables)
    );
    let walls_ok = walls.no_user_execute && walls.no_user_access && walls.hide_tables;
    BOOT_OK.store(
        check_ok && long_mode && nx && walls_ok && booted.free_bytes > 0,
        Ordering::Relaxed,
    );

    banner::draw(&banner::Summary {
        usable_mib: boot.usable_bytes() >> 20,
        free_mib: booted.free_bytes >> 20,
        stack_guards: booted.stack_guards,
        ticks_per_second: TICKS_PER_SECOND,
        walls: walls_ok,
        nx,
        check_ok,
    });

    // The kernel-wall attacks run in ring 0 and never reach user mode.
    if let Some(name @ ("null" | "wx" | "nx" | "stray" | "stack")) = boot.value("test") {
        attack(name);
    }

    // Everything else runs under the scheduler. Michael comes first, with
    // Writs to hear from and reply to the task he watches.
    let michael = spawn_user(
        "michael",
        &booted.michael,
        0,
        &[
            Writ::Endpoint {
                endpoint: REQUEST_EP,
                send: false,
                recv: true,
                badge: 0,
            },
            Writ::Endpoint {
                endpoint: REPLY_EP,
                send: true,
                recv: false,
                badge: 0,
            },
        ],
    );

    let watch = match boot.value("test") {
        Some("taskstack") => {
            // A kernel task that overflows its stack: a ring-0 fault, so
            // the Keep stops rather than ending just the task.
            kprintln!("[keep] test: overflowing a kernel task's stack");
            spawn_kernel("overflow", overflow, 0);
            None
        }
        Some("crash") => Some((
            spawn_check(&booted.check, abi::check::CRASH, michael),
            Watch::Crash,
        )),
        _ => {
            let check = spawn_check(&booted.check, abi::check::CALLS, michael);
            spawn_vault(&booted.vault);
            Some((check, Watch::Checks))
        }
    };

    arch::apic::start_timer(arch::idt::TIMER_VECTOR, tick_counts);
    kprintln!(
        "[keep] sched: timer on, {TICKS_PER_SECOND} ticks a second; the boot thread is now the idle task"
    );

    match watch {
        Some((check, how)) => supervise(michael, check, how, check_ok),
        None => sched::become_idle(),
    }
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "OFF" }
}

/// Watch the ring-3 test program finish, report the result, and in
/// self-test mode end the run.
fn supervise(michael: usize, check: usize, how: Watch, check_ok: bool) -> ! {
    let outcome = loop {
        arch::cpu::wait_for_interrupt();
        if let Some(outcome) = sched::outcome(check) {
            break outcome;
        }
    };
    let michael_alive = sched::is_alive(michael);
    let passed = match how {
        Watch::Checks => outcome == Outcome::Exited(0),
        Watch::Crash => outcome == Outcome::Faulted && michael_alive,
    };
    match (how, outcome) {
        (Watch::Checks, Outcome::Exited(code)) => {
            kprintln!("[keep] user: the ring-3 test program ran its checks and exited with {code}")
        }
        (Watch::Crash, Outcome::Faulted) => kprintln!(
            "[keep] user: the ring-3 test program crashed; the Keep ended it, and Michael is {}",
            if michael_alive {
                "still on watch"
            } else {
                "GONE"
            }
        ),
        (_, Outcome::Exited(code)) => {
            kprintln!("[keep] user: the ring-3 test program exited with {code}, unexpectedly")
        }
        (_, Outcome::Faulted) => {
            kprintln!("[keep] user: the ring-3 test program faulted, unexpectedly")
        }
    }
    kprintln!(
        "[keep] user: ring 3 {}",
        if passed { "works" } else { "FAILED" }
    );
    banner::draw_checks(check_ok, Some(passed));

    if SELFTEST.load(Ordering::Relaxed) {
        let selftest = BOOT_OK.load(Ordering::Relaxed) && passed;
        kprintln!(
            "[keep] selftest: {}",
            if selftest { "passed" } else { "failed" }
        );
        arch::qemu::exit(if selftest {
            arch::qemu::EXIT_SUCCESS
        } else {
            arch::qemu::EXIT_FAILURE
        });
    }
    if !passed {
        fail_closed();
    }
    kprintln!("[keep] all quiet. Drawbridge raised.");
    sched::become_idle()
}

fn log_memory_map(boot: &BootInfo) {
    for r in boot.regions() {
        kprintln!(
            "[keep] memory: {:#011x}..{:#011x} {:>9} KiB {}",
            r.start,
            r.start.saturating_add(r.len),
            r.len >> 10,
            if r.usable { "usable" } else { "reserved" }
        );
    }
    if boot.dropped() > 0 {
        kprintln!("[keep] memory: {} more regions ignored", boot.dropped());
    }
    kprintln!("[keep] memory: {} MiB usable", boot.usable_bytes() >> 20);
}

struct Booted {
    free_bytes: u64,
    /// Stacks with an unmapped guard below them.
    stack_guards: usize,
    michael: user::Program,
    check: user::Program,
    vault: user::Program,
}

/// Replace the boot page tables with the Keep's own, load the user
/// programs into address spaces of their own, then seal the frame
/// allocator: from here on the Keep allocates nothing. `apic` is the local
/// APIC's register page, which the new tables map.
fn setup_memory(boot: &BootInfo, apic: u64) -> Booted {
    let layout = arch::layout::kernel();
    let reserved = [
        Range {
            start: 0,
            end: LOW_MEMORY,
        },
        Range {
            start: layout.phys_start,
            end: layout.phys_end,
        },
    ];
    let mut frames = Frames::new(boot, &reserved, BOOT_MAP_LIMIT);
    let kernel = match memory::build(&mut frames, boot.top_of_ram(), apic) {
        Ok(kernel) => kernel,
        Err(e) => {
            kprintln!("[keep] memory: could not build page tables: {e}");
            fail_closed();
        }
    };
    if let Err(e) = arch::paging::load_kernel_space(&kernel.space, &arch::must_stay_mapped()) {
        kprintln!("[keep] memory: not switching page tables: {e}");
        fail_closed();
    }
    sched::set_kernel_space(kernel.space.root());
    kprintln!(
        "[keep] memory: own page tables loaded: code read+execute, constants read-only, data no-execute"
    );
    kprintln!(
        "[keep] memory: lower half and null page unmapped, {} stack guard pages, {} MiB physical window",
        kernel.guard_pages,
        kernel.window_bytes >> 20
    );

    let michael = load_program("michael", programs::MICHAEL, &kernel.space, &mut frames);
    let check = load_program("check", programs::CHECK, &kernel.space, &mut frames);
    let vault = load_program("vault", programs::VAULT, &kernel.space, &mut frames);

    frames.seal();
    kprintln!(
        "[keep] memory: {} task stacks of {} KiB, each above a {} KiB unmapped gap; local APIC uncached",
        kernel.task_stacks,
        arch::layout::STACK_SIZE >> 10,
        (arch::layout::STACK_SLOT - arch::layout::STACK_SIZE) >> 10
    );
    kprintln!(
        "[keep] memory: {} KiB set aside at boot, {} MiB free; allocator sealed",
        frames.used_bytes() >> 10,
        frames.free_bytes() >> 20
    );
    Booted {
        free_bytes: frames.free_bytes(),
        stack_guards: kernel.guard_pages + kernel.task_stacks,
        michael,
        check,
        vault,
    }
}

/// Load one embedded user program, or stop if it won't load.
fn load_program(
    name: &str,
    elf: &[u8],
    kernel: &arch::paging::AddressSpace,
    frames: &mut Frames,
) -> user::Program {
    match user::load(elf, kernel, frames) {
        Ok(program) => {
            kprintln!(
                "[keep] user: loaded {name}: entry {:#x}, stack top {:#x}",
                program.entry,
                program.stack_top
            );
            program
        }
        Err(e) => {
            kprintln!("[keep] user: can't load {name}: {e}; stopping");
            fail_closed();
        }
    }
}

/// Turn on the local APIC and measure its timer against the PIT. Returns
/// the count for one tick; the timer starts with the scheduler.
fn setup_timer() -> u32 {
    arch::apic::init(arch::idt::SPURIOUS_VECTOR);
    match arch::apic::calibrate(TICK_MS) {
        Ok(counts) => {
            let bus_mhz = u64::from(counts) * arch::apic::DIVIDER / (u64::from(TICK_MS) * 1000);
            kprintln!(
                "[keep] timer: local APIC timer calibrated against the PIT: {counts} counts per {TICK_MS} ms tick, {bus_mhz} MHz bus"
            );
            counts
        }
        Err(e) => {
            kprintln!("[keep] timer: {e}; stopping");
            fail_closed();
        }
    }
}

/// Start a kernel task, or stop if there's no slot for it.
fn spawn_kernel(name: &'static str, entry: extern "C" fn(u64) -> !, arg: u64) -> usize {
    match sched::spawn(name, entry, arg) {
        Some(slot) => slot,
        None => {
            kprintln!("[keep] sched: no free slot for task {name}; stopping");
            fail_closed();
        }
    }
}

/// Start a user task with the Writs in `caps`, or stop if there's no slot
/// for it.
fn spawn_user(name: &'static str, program: &user::Program, arg: u64, caps: &[Writ]) -> usize {
    match sched::spawn_user(name, program, arg, caps) {
        Some(slot) => {
            kprintln!("[keep] sched: task {slot} ({name}) ready in ring 3");
            slot
        }
        None => {
            kprintln!("[keep] sched: no free slot for task {name}; stopping");
            fail_closed();
        }
    }
}

/// Start the `check` task in `mode`, give it Writs to trade messages with
/// the supervisor, and give the supervisor a Task Writ to watch it. Its
/// send badge is its own slot, so the supervisor learns who reported in.
fn spawn_check(program: &user::Program, mode: u64, michael: usize) -> usize {
    let check = spawn_user("check", program, mode, &[]);
    sched::grant(
        check,
        0,
        Writ::Endpoint {
            endpoint: REQUEST_EP,
            send: true,
            recv: false,
            badge: check as u64,
        },
    );
    sched::grant(
        check,
        1,
        Writ::Endpoint {
            endpoint: REPLY_EP,
            send: false,
            recv: true,
            badge: 0,
        },
    );
    sched::grant(michael, 2, Writ::Task { slot: check });
    check
}

/// Start the `vault` storage service, with an I/O Writ for the ATA bus so
/// it can drive the disk from ring 3.
fn spawn_vault(program: &user::Program) -> usize {
    spawn_user(
        "vault",
        program,
        0,
        &[Writ::Io {
            base: ATA_IO_BASE,
            count: ATA_IO_COUNT,
        }],
    )
}

/// The kernel-task-stack test: recurse until the task's stack runs out.
extern "C" fn overflow(_: u64) -> ! {
    let depth = recurse(0);
    kprintln!("[keep] test: recursion ended at depth {depth}");
    kprintln!("[keep] test: taskstack: the access was NOT stopped");
    fail_closed()
}

/// Raise a breakpoint and check the trap handler saw it and came back.
fn self_check() -> bool {
    let before = trap::breakpoints();
    arch::cpu::breakpoint();
    trap::breakpoints() == before.wrapping_add(1)
}

/// Deliberate attacks on the Keep's own protections, chosen with
/// `test=NAME` on the command line. Each should end in a fault that stops
/// the machine; getting past one means a protection is missing.
fn attack(name: &str) -> ! {
    match name {
        "null" => {
            kprintln!("[keep] test: reading address 0");
            arch::cpu::read_test(0);
        }
        "wx" => {
            let code = keep_main as fn(bool, BootInfo) -> ! as usize as u64;
            kprintln!("[keep] test: writing to the Keep's code at {code:#x}");
            arch::cpu::write_test(code);
        }
        "nx" => {
            let data = core::ptr::addr_of!(NX_PROBE) as u64;
            kprintln!("[keep] test: executing data at {data:#x}");
            arch::cpu::exec_test(data);
        }
        "stray" => {
            kprintln!("[keep] test: raising an interrupt nothing handles");
            arch::cpu::stray_interrupt_test();
        }
        "stack" => {
            kprintln!("[keep] test: overflowing the stack");
            let depth = recurse(0);
            kprintln!("[keep] test: recursion ended at depth {depth}");
        }
        _ => kprintln!("[keep] test: there is no test named {name:?}"),
    }
    kprintln!("[keep] test: {name}: the access was NOT stopped");
    fail_closed()
}

/// Recurse until the stack runs into its guard page.
#[inline(never)]
fn recurse(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 32]);
    if core::hint::black_box(depth) == u64::MAX {
        return 0;
    }
    recurse(depth + 1).wrapping_add(frame[0])
}

/// Stop safely. In self-test mode, tell QEMU the run failed.
pub fn fail_closed() -> ! {
    if SELFTEST.load(Ordering::Relaxed) {
        arch::qemu::exit(arch::qemu::EXIT_FAILURE);
    }
    arch::cpu::halt_forever()
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kprintln!("[keep] panic: {info}");
    fail_closed()
}
