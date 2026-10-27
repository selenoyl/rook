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
  - a **Task Writ** lets one task watch another's state;
  - an **I/O Writ** grants a task a range of I/O ports, so a driver can
    run in ring 3 and reach only its own device. The Keep allocates
    nothing for any of this — the endpoints and wait queues are set aside
    at boot.
- **Raises the walls between ring 0 and ring 3**: SMEP (ring 0 can't run
  ring-3 code), SMAP (ring 0 can't read ring-3 memory except through one
  checked window), UMIP (ring 3 can't read the descriptor-table
  registers), and the floating-point unit off (no FP state to leak
  between tasks).
- **Isolates faults.** A fault in a user task ends just that task and
  the Keep carries on; only a fault in the Keep's own code stops the
  machine. The log names the faulting address, whether it hit a stack
  guard, and which task was running.
- **Hands out randomness.** A ChaCha20 CSPRNG, seeded at boot from the
  CPU's hardware generator (RDSEED, else RDRAND), backs a `random` system
  call. It rekeys on every draw, so earlier output can't be recovered from
  a later key. Drawbridge's ephemeral keys are drawn from it.
- Starts **Michael**, the supervisor, as the first user task. He opens a
  Drawbridge session with the task he watches — authenticating it over an
  endpoint and trading a sealed message — and checks on it through a Task
  Writ. The ring-3 test program checks the system calls, that bad
  arguments and ungranted Writs are refused, that the timer preempts a
  ring-3 loop, that the cryptography is correct, that it can open a
  Drawbridge session with Michael, and that it can read a file from the
  Vault — all over the Keep's message passing.
- Starts the **Vault**, a storage service: it owns the disk through an I/O
  Writ, drives an ATA controller and mounts a filesystem entirely in ring
  3, and serves files to other tasks over an endpoint. A driver and a
  filesystem as an ordinary user program, not privileged code.

## Cryptography (`crypto/`)

The first layer of Rook's security architecture: a `no_std`,
forbid-unsafe library written from the specifications, since Rook vendors
no crates.

- **SHA-256 and SHA-512** (FIPS 180-4), **SHA3-256/512 and SHAKE128/256**
  (FIPS 202), **HMAC** (RFC 2104) and **HKDF** (RFC 5869).
- **ChaCha20**, **Poly1305**, and the **ChaCha20-Poly1305 AEAD**
  (RFC 8439).
- **X25519** Diffie-Hellman (RFC 7748) and **Ed25519** signatures
  (RFC 8032), over a shared 2^255-19 field.
- **ML-KEM-768** (FIPS 203), the post-quantum key-encapsulation mechanism —
  the quantum-resistant half of Rook's hybrid key exchange.
- The symmetric pieces and the X25519 ladder are constant-time — no step
  branches on a key or a secret. Ed25519 signing is not yet (its
  double-and-add walks the scalar's bits), and the code says so.

Every primitive is checked against the official RFC/NIST **known-answer
vectors** two ways: as host unit tests (`make test` runs them), and by
`crypto::self_test()`, which the `check` program runs **in ring 3 at every
boot**. ML-KEM-768 is pinned to the NIST ACVP vectors — the full key and
ciphertext on the host, and the hashes of a keygen's outputs plus a
round-trip in ring 3. A single wrong constant or rotation fails a vector,
so this is a real correctness gate. It has not been through a security
audit, so — as the design doc itself budgets — nothing here protects
anything real until it has.

## Drawbridge (`drawbridge/`)

The protocol two Rook tasks (eventually two angels) use to talk securely.
Each holds a long-term Ed25519 identity; a three-message handshake gives
them a shared, encrypted session:

- A **hybrid, post-quantum key exchange**: each side contributes a fresh
  **ephemeral X25519** key, and the initiator also offers an ephemeral
  **ML-KEM-768** encapsulation key that the responder encapsulates to. The
  session key is derived from *both* shared secrets, so recovering it means
  breaking a classical **and** a post-quantum problem. The ephemeral keys
  are per-session, so the session stays **forward-secret** even if an
  identity key is later stolen.
- Each side **signs the transcript** — every public value of the handshake
  — with its identity key, for **mutual authentication** bound to this
  exact exchange. The identities and signatures travel encrypted, so an
  eavesdropper learns neither, and a valid tag also confirms the peer
  agreed the same key. (Identity authentication is still classical Ed25519;
  post-quantum signatures, SLH-DSA, come next.)
- The data channel numbers every message with a per-direction counter, so
  a **replayed or reordered** message is refused.

This is a SIGMA-style design hybridized with ML-KEM, the same shape the
post-quantum work in TLS and Noise is taking, built only from `crypto`
above. `drawbridge::self_test()` runs a full handshake and sealed exchange
**in ring 3 at every boot**, and the host tests additionally prove
tampering (of both the X25519 and the ML-KEM parts), replay, reorder, a
pinned-identity mismatch and a low-order point are all caught. The caller
supplies the random seed — in the running demo, Michael and `check` draw
theirs from the Keep's CSPRNG. Like the crypto beneath it, the protocol is
**not audited**.

And it already runs **between two separate tasks over real endpoints**: at
every boot, `check` (the initiator) and `michael` (the responder) run the
handshake through the Keep's message passing — each pinning the other's
identity — and trade a sealed message, with a small fragmentation layer
(`send_blob`/`recv_blob`) splitting each handshake message across the
register-sized IPC packets. The two use fixed demo identity keys, clearly
marked as such; real ones come from per-device entropy and Castling.

The key exchange is already hybrid; **SLH-DSA** (post-quantum signatures)
comes next, to make the identity authentication quantum-resistant too.

## Storage: the Vault (`vault/`)

The Vault is Rook's first general OS service, and it shows the microkernel
model end to end: a **device driver and a filesystem running in ring 3**,
reaching the disk only through a capability.

- The `vault` crate is the filesystem: a superblock with a fixed
  directory, files in contiguous extents, bump allocation. It rides on a
  `BlockDevice` trait, so it is the same code on real hardware and over an
  in-memory device in its 14 host tests. It treats the disk as untrusted —
  a corrupt superblock or an out-of-range entry is refused, not followed.
- `user::ata` is a small PIO, polled, LBA28 ATA driver. It is a *user*
  program: it reaches the controller only through the Keep's I/O system
  calls, holding an I/O Writ for the primary bus's ports and nothing else.
- The `vault` task puts the two together — it mounts the disk and serves
  files to other tasks over an endpoint. At boot it reports the disk's
  geometry and files, and `check` reads one back over IPC.

So the only code that touches the disk hardware is a ring-3 task the Keep
could end like any other; a bug there cannot corrupt the Keep. The on-disk
image is built by `tools/mkvault.py` and attached to QEMU as an IDE drive.

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
| `keep/src/random.rs` | The ChaCha20 CSPRNG, seeded from the CPU's hardware RNG |
| `keep/src/programs.rs` | The user programs' ELF images, embedded by `keep/build.rs` |
| `keep/src/trap.rs` | What to do on each CPU exception |
| `keep/src/banner.rs` | The boot screen |
| `abi/` | The system-call interface (call numbers, errors, message and status encodings), shared by the Keep and the user programs |
| `user/` | Rook's user programs: Michael the supervisor, `check` the ring-3 test program, and `vault` the storage service; `user/src/ata.rs` is the ring-3 ATA driver. `user/src/sys.rs` is the other place `unsafe` is allowed |
| `crypto/` | Rook's cryptography, from the specs: SHA-2, SHA-3/SHAKE, HMAC, HKDF, ChaCha20-Poly1305, X25519, Ed25519, ML-KEM-768, verified against the official vectors. No `unsafe`, no external crates |
| `drawbridge/` | Rook's authenticated, encrypted session protocol: a SIGMA-style handshake and a sealed data channel, built on `crypto`. No `unsafe` |
| `vault/` | The Vault filesystem over a `BlockDevice` trait, host-tested. No `unsafe` |
| `tools/mkvault.py` | Builds a raw disk image holding a Vault filesystem |
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

The Keep's privileged core is in place; the crypto foundation, the
Drawbridge handshake and a ring-3 storage service are down. What's left
builds on top:

1. **Finish the post-quantum suite**: SLH-DSA signatures beside ML-KEM-768,
   then a **hybrid Drawbridge** handshake combining X25519 and ML-KEM so a
   recorded session stays secret even against a future quantum computer.
2. **A fuller Vault**: writes and deletion that reclaim space, and
   carrying its files over a Drawbridge session so storage is encrypted
   and authenticated end to end.
3. The angels as real tasks (Michael spawning, watching and restarting
   the others, then Gabriel and Raphael), which also needs runtime task
   spawn and reclaiming an exited task's slot.
4. Fuzz the parsers, and boot under GRUB on real hardware (x2APIC and a
   PIT-less timer source are still to do).
