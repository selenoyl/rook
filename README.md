# Rook

Rook is a from-scratch, security-first operating system and network
protocol, written in Rust. The design lives in the
[Rook: Security & Design Principles](https://claude.ai/artifact/Ddf9ZD5sMHLMDQuUsa73kh)
doc. This repository starts with the Keep, Rook's microkernel, as an
x86-64 kernel running in QEMU, with its first programs running in ring 3
and talking to each other through the Keep.

The Keep does everything the design asks a microkernel to do privileged
— **scheduling, memory, interrupts, and message passing** — and gates it
all with **Writs** (capabilities). On top of it, the security
architecture has begun: a from-scratch **cryptography** library, checked
against the official test vectors. The angels, Drawbridge and the network
are built from here, as user programs.

## What the Keep does today (v0.6)

- Boots as a Multiboot kernel. A short assembly trampoline clears .bss,
  maps the first GiB twice (identity, and the higher half at
  `0xFFFFFFFF80000000`, where the Keep is linked), turns on long mode,
  no-execute and paging, and jumps to Rust in the higher half.
- Logs to the serial port (COM1).
- Reads the boot loader's memory map and command line. They're parsed
  under the doc's input-handling rules: bounds-checked, no panics, and
  malformed data is dropped.
- Moves the legacy 8259 interrupt controllers off the CPU exception
  vectors and masks them, then installs a GDT with ring-0 and ring-3
  segments, a TSS, and an IDT: the 32 exception gates plus the timer,
  yield, system-call and spurious-interrupt gates.
- Builds a frame allocator from the memory map and its own page tables:
  - code is read+execute, constants read-only, data and stacks
    read+write but never executable (write-xor-execute);
  - the lower half, including the null page, is unmapped;
  - the page under each stack is left unmapped, so an overflow faults
    instead of silently overwriting memory;
  - the local APIC's registers are mapped uncached;
  - all RAM is mapped, no-execute, in a window at `0xFFFF800000000000`.
- Checks the new tables map everything the CPU touches before switching
  to them, then seals the allocator: the Keep allocates nothing after
  boot.
- Calibrates the local APIC timer against the PIT and runs it at 100
  ticks a second; the scheduler is round robin over a fixed table of 16
  slots, and the timer preempts the running task every tick.
- **Runs programs in ring 3.** The Keep ships two user programs built as
  separate, unprivileged ELF executables and embedded in its image:
  - a **Gatehouse ELF loader** parses each one as untrusted input and
    refuses anything malformed — no segment that is both writable and
    executable, nothing outside user space, nothing misaligned;
  - each program gets an **address space of its own** that shares the
    Keep's higher half (so the Keep stays mapped) and has the program's
    segments and a guard-paged stack in the lower half;
  - a program reaches the Keep only through **system calls** (`int 0x80`):
    log, yield, sleep, exit, now, send, recv and watch. Every argument is
    checked; a buffer a task names is confirmed to lie in the task's own
    memory before the Keep reads it, and anything refused comes back as an
    error, never a fault.
- **Passes messages between tasks**, gated by **Writs** (capabilities):
  - a task holds a small table of Writs the Keep placed there and names
    one by a handle; it can't forge one or reach anything it has no Writ
    for;
  - tasks meet at **endpoints**. A task with a send Writ and one with a
    receive Writ rendezvous, and the Keep hands a short message (four
    words) from one to the other, stamped with the sender's badge;
  - a **Task Writ** lets one task watch another's state. The Keep
    allocates nothing for any of this — the endpoints and wait queues are
    set aside at boot.
- **Raises the walls between ring 0 and ring 3**: SMEP (ring 0 can't run
  ring-3 code), SMAP (ring 0 can't read ring-3 memory except through one
  checked window), UMIP (ring 3 can't read the descriptor-table
  registers), and the floating-point unit off (no FP state to leak
  between tasks).
- **Isolates faults.** A fault in a user task ends just that task and
  the Keep carries on; only a fault in the Keep's own code stops the
  machine. The log names the faulting address, whether it hit a stack
  guard, and which task was running.
- Starts **Michael**, the supervisor, as the first user task. He hears a
  task report in over an endpoint, checks on it through a Task Writ, and
  replies. The ring-3 test program checks the system calls, that bad
  arguments and ungranted Writs are refused, that the timer preempts a
  ring-3 loop, that it can trade a message with Michael, and that the
  cryptography is correct.

## Cryptography (`crypto/`)

The first layer of Rook's security architecture: a `no_std`,
forbid-unsafe library written from the specifications, since Rook vendors
no crates.

- **SHA-256 and SHA-512** (FIPS 180-4), **HMAC** over both (RFC 2104), and
  **HKDF** (RFC 5869).
- **ChaCha20**, **Poly1305**, and the **ChaCha20-Poly1305 AEAD**
  (RFC 8439).
- **X25519** Diffie-Hellman (RFC 7748) and **Ed25519** signatures
  (RFC 8032), over a shared 2^255-19 field.
- The symmetric pieces and the X25519 ladder are constant-time — no step
  branches on a key or a secret. Ed25519 signing is not yet (its
  double-and-add walks the scalar's bits), and the code says so.

Every primitive is checked against the official RFC/NIST **known-answer
vectors** two ways: as host unit tests (`make test` runs them), and by
`crypto::self_test()`, which the `check` program runs **in ring 3 at every
boot**. A single wrong constant or rotation fails a vector, so this is a
real correctness gate. It has not been through a security audit, so — as
the design doc itself budgets — nothing here protects anything real until
it has.

## Drawbridge (`drawbridge/`)

The protocol two Rook tasks (eventually two angels) use to talk securely.
Each holds a long-term Ed25519 identity; a three-message handshake gives
them a shared, encrypted session:

- A fresh **ephemeral X25519** key each way, so the session key is
  **forward-secret**: recording the traffic and later stealing an identity
  key still doesn't reveal it.
- Each side **signs the transcript** (both ephemeral keys) with its
  identity key — **mutual authentication**, bound to this exact exchange.
  The identities and signatures travel encrypted, so an eavesdropper
  learns neither, and a valid tag also confirms the peer agreed the same
  key.
- The data channel numbers every message with a per-direction counter, so
  a **replayed or reordered** message is refused.

This is a SIGMA-style design, the same shape as the handshakes in TLS 1.3
and Noise, built only from `crypto` above. `drawbridge::self_test()` runs a
full handshake and sealed exchange **in ring 3 at every boot**, and the
host tests additionally prove tampering, replay, a swapped ephemeral, a
pinned-identity mismatch and a low-order point are all caught. The caller
supplies the random secret keys; this crate has no entropy source, and
like the crypto beneath it, it is **not audited**.

The quantum-resistant pieces (ML-KEM, SLH-DSA) come next, and then
Drawbridge carried over real endpoints between separate tasks.

## Build, run, test

You need rustup (the pinned toolchain in `rust-toolchain.toml` installs
itself), QEMU (`qemu-system-x86_64`), binutils (`objcopy`) and Python 3.
Pillow is optional, for screenshots. The Keep is run under `-cpu max` so
QEMU offers SMEP, SMAP and UMIP.

| Command | What it does |
| --- | --- |
| `make` | Builds the user programs, then `build/keep.bin` with them embedded |
| `make run` | Boots it in a QEMU window, with the boot log in your terminal |
| `make test` | Format and clippy checks, the review checks below, and the boot tests |
| `make screen` | Boots headless and saves the screen to `build/screen.png` |

The boot tests run QEMU eight times. Two must exit with QEMU status 33,
which means success: a normal self-test boot (ring 3 verified), and a
boot where the ring-3 test program crashes on purpose and the Keep ends
it and keeps Michael running. The other six attack the Keep's own
protections with `test=NAME` and must log the fault and exit with 35,
the fail-closed code:

| Test | The attack | What stops it |
| --- | --- | --- |
| `null` | Read address 0 | The null page is unmapped |
| `wx` | Write to the Keep's own code | Code pages are read-only |
| `nx` | Execute a `ret` stored in data | Data pages are no-execute |
| `stack` | Recurse until the boot stack runs out | The guard page faults; the double fault runs on its own stack |
| `taskstack` | Recurse in a kernel task until its stack runs out | The unmapped gap below it faults, and the log names the task |
| `stray` | Raise interrupt 0x40, which has no gate | The empty IDT entry raises a general protection fault |

QEMU's Multiboot loader only accepts 32-bit ELF files, and a 32-bit ELF
can't describe code linked at `0xFFFFFFFF80000000`. So the build ships a
flat image, `build/keep.bin`, whose Multiboot header gives the load
addresses; the loader parses no ELF at all.

## Layout

| Path | What it is |
| --- | --- |
| `keep/src/main.rs` | Boot sequence, self-checks, the protection attacks, fail-closed policy, supervising the first user tasks |
| `keep/src/arch/` | Everything low-level: boot assembly, CPU and the ring-0/3 walls, GDT, IDT and entry stubs, page tables, the virtual memory layout, the local APIC and its timer, the legacy PIC and PIT, saved task and syscall state, the interrupt-safe cell, port I/O, serial, VGA, Multiboot access. One of the two places `unsafe` is allowed |
| `keep/linker.ld` | Places the Keep in the higher half, each section on its own pages |
| `keep/src/bootinfo.rs` | Parser for the boot loader's memory map and command line |
| `keep/src/frames.rs` | The boot-time frame allocator |
| `keep/src/memory.rs` | Builds the Keep's address space: section permissions, guard pages, task stacks, device registers, the physical window |
| `keep/src/sched.rs` | The scheduler: kernel and user tasks, address-space and kernel-stack switching, Writs, endpoints and message passing |
| `keep/src/user.rs` | The Gatehouse ELF loader that builds a user program's address space |
| `keep/src/syscall.rs` | The system calls, each argument and Writ checked |
| `keep/src/programs.rs` | The user programs' ELF images, embedded by `keep/build.rs` |
| `keep/src/trap.rs` | What to do on each CPU exception |
| `keep/src/banner.rs` | The boot screen |
| `abi/` | The system-call interface (call numbers, errors, message and status encodings), shared by the Keep and the user programs |
| `user/` | Rook's first user programs: Michael the supervisor, and `check`, the ring-3 test program. `user/src/sys.rs` is the other place `unsafe` is allowed |
| `crypto/` | Rook's cryptography, from the specs: SHA-2, HMAC, HKDF, ChaCha20-Poly1305, X25519, Ed25519, verified against the official vectors. No `unsafe`, no external crates |
| `drawbridge/` | Rook's authenticated, encrypted session protocol: a SIGMA-style handshake and a sealed data channel, built on `crypto`. No `unsafe` |
| `keep/assets/`, `tools/shadow_art.py` | Rufus (the Rook logo) and the ROOK wordmark as block art, and the tool that redraws the logo from `logo-grid.txt` |
| `UNSAFE.md` | Every unsafe use, and why it is sound |
| `tools/check.py` | Review checks: unsafe only in the low-level modules and listed in UNSAFE.md; the Keep under 10,000 lines |
| `tests/boot_test.py` | Headless boot tests |

## Design rules this code already follows

- Toolchain pinned to Rust 1.97.0; no external crates.
- Release profile: `overflow-checks = true`, `panic = "abort"`,
  `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`.
- `unsafe` only in `keep/src/arch` and `user/src/sys.rs`. Every block
  carries a `// SAFETY:` comment, enforced by clippy, and a row in
  `UNSAFE.md`, enforced by `tools/check.py`. Everything else uses
  `#![forbid(unsafe_code)]`.
- The code that reads untrusted input — the boot-info parser and the ELF
  loader — denies `clippy::indexing_slicing`,
  `clippy::arithmetic_side_effects`, `unwrap_used` and `expect_used`.
- Assembly only for boot and interrupt entry. Task switching happens in
  the interrupt entry path, which restores whichever saved frame the
  scheduler hands back.

## Next steps

The Keep's privileged core is in place; the crypto foundation and the
Drawbridge handshake are down. What's left builds on top:

1. **Quantum-resistant crypto**: ML-KEM and SLH-DSA, to sit beside X25519
   and Ed25519 as the other half of Rook's hybrid.
2. **Drawbridge over endpoints**: carry the handshake and sealed channel
   between two separate ring-3 tasks through the Keep's message passing,
   not just within one task — which needs a small layer to fragment a
   message across the register-sized IPC packets.
3. **General OS services**: a block-device driver and a simple filesystem,
   as user-space services reached through Writs, so programs and data can
   live on disk instead of being baked into the image.
4. The angels as real tasks (Michael spawning, watching and restarting
   the others, then Gabriel and Raphael), which also needs runtime task
   spawn and reclaiming an exited task's slot.
5. Fuzz the parsers, and boot under GRUB on real hardware (x2APIC and a
   PIT-less timer source are still to do).
