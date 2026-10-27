# Unsafe code in Rook

Rook's rule: `unsafe` is allowed only in named low-level modules, and
every use carries a `// SAFETY:` comment and an entry here. The low-level
modules are `keep/src/arch` (the Keep) and `user/src/sys.rs` (the user
programs' entry point and system-call instruction); everything else
compiles under `#![forbid(unsafe_code)]`.

`tools/check.py` fails if the per-file counts in this table and the code
disagree, so adding an `unsafe` use means adding (or updating) a row.

| File | Where | Count | What it does | Why it is sound |
| --- | --- | --- | --- | --- |
| `keep/src/arch/apic.rs` | `read`, `write` | 2 | Volatile reads and writes of the local APIC's registers | The register page is mapped uncached at `APIC_VIRT`; every offset is a fixed, aligned register inside it, and no Rust object lives there. Before the Keep's tables load the page is unmapped, so a stray call faults rather than corrupting. |
| `keep/src/arch/boot.rs` | `keep_entry` | 1 | `#[unsafe(no_mangle)]` gives the entry point a fixed symbol name | The boot assembly calls it by that name with the C ABI it declares; no other symbol is named `keep_entry`. |
| `keep/src/arch/cpu.rs` | `halt_forever` | 1 | `cli; hlt` | Stops the CPU; touches no memory. |
| `keep/src/arch/cpu.rs` | `disable_interrupts`, `restore_interrupts` | 2 | Read RFLAGS and `cli`; `sti` | Only hold interrupts back and let them through again; both are compiler barriers, so the critical section stays put. |
| `keep/src/arch/cpu.rs` | `wait_for_interrupt` | 1 | `sti; hlt` | `sti` takes effect after the next instruction, so no interrupt is lost; the IDT is loaded first. |
| `keep/src/arch/cpu.rs` | `breakpoint` | 1 | `int3` | Traps into the breakpoint gate, whose handler returns. |
| `keep/src/arch/cpu.rs` | `read_test`, `write_test`, `exec_test` | 3 | The kernel-wall tests' deliberate faults | Each reads, writes-back, or calls a `ret`, so even if a protection were missing nothing changes; each is expected to fault, and the handler stops the machine. |
| `keep/src/arch/cpu.rs` | `stray_interrupt_test` | 1 | `int 0x40`, a vector with no gate | Its IDT entry is zero, so the CPU raises a general protection fault, which stops the machine. |
| `keep/src/arch/cpu.rs` | `cr2`, `cr0`, `read_cr4` | 3 | Read control registers | Reads have no side effects. |
| `keep/src/arch/cpu.rs` | `rdmsr` | 1 | Read a model-specific register | Only called for EFER and IA32_APIC_BASE, which exist on a 64-bit CPU with a local APIC; reads have no side effects. |
| `keep/src/arch/cpu.rs` | `has_apic`, `cpuid_leaf7` | 3 | CPUID leaves 1 and 7 | Both leaves only report features; rbx, which the compiler reserves, is saved and restored around each. |
| `keep/src/arch/cpu.rs` | `harden` | 1 | Set CR4 (SMEP, SMAP, UMIP) and CR0 (write-protect, trap FP) | Only raises the walls between ring 0 and ring 3 and traps FP use; paging and long mode are left on. |
| `keep/src/arch/cpu.rs` | `write_cr4`, `write_cr0` | 4 | The `unsafe fn` wrappers and their control-register writes | `unsafe` because a bad value could disable paging; the one caller, `harden`, sets only supported feature bits and keeps paging on. |
| `keep/src/arch/cpu.rs` | `with_user_access` | 2 | `stac` / `clac` | Lifts and restores SMAP around one checked user access; only valid because SMAP is on, which the caller confirmed. |
| `keep/src/arch/cpu.rs` | `copy_from_user` | 1 | Read one validated user byte | The caller checked the whole range is present, user-owned memory in the current space; the index stays inside it. |
| `keep/src/arch/gdt.rs` | `init` | 2 | Fill the TSS and GDT, then `lgdt`, reload CS/DS/ES/SS, `ltr` | Runs once on the only CPU with interrupts off, before anything reads them; the new GDT keeps the boot selectors. |
| `keep/src/arch/gdt.rs` | `set_kernel_stack` | 1 | Write the TSS's RSP0 | `RSP0` points at the TSS field, set once by `init`; the CPU reads it only on a ring-3 trap, and this writes it with interrupts off. |
| `keep/src/arch/idt.rs` | `isr_stub_table` | 1 | `unsafe extern` declaration of the stub table | Declares a read-only table of (vector, stub) pairs defined in this file's assembly. |
| `keep/src/arch/idt.rs` | `init` | 3 | Read the stub table, fill the IDT, `lidt` | The table is never written; the IDT is filled once with interrupts off before it loads, indexing bounds-checked. |
| `keep/src/arch/idt.rs` | `keep_trap` | 2 | `#[unsafe(no_mangle)]`, and reads the vector, error code and RIP from the frame | The entry stubs call it by name with a pointer to the frame they just pushed, which stays in place until a frame is restored. |
| `keep/src/arch/idt.rs` | `dispatch` | 1 | Read the saved `cs` to see which ring faulted | As for `keep_trap`; only the low two bits (the privilege) are used. |
| `keep/src/arch/idt.rs` | `tables` | 1 | Read the stub table's first entry | The table is never written; the value is an address, used only to check the new page tables map the stubs. |
| `keep/src/arch/layout.rs` | linker symbols | 1 | `unsafe extern` declaration of the section-boundary and guard-page symbols | Only their addresses are taken (with `&raw const`), never their contents. |
| `keep/src/arch/multiboot.rs` | `read` | 3 | View the loader's info block, memory map and command line as byte slices | The Multiboot magic vouches for the info address; every range is bounded and checked to lie in identity-mapped memory, never reused. |
| `keep/src/arch/paging.rs` | `read`, `write` | 2 | Volatile reads and writes of page-table entries, and of pages being zeroed or filled | Every frame is one this module took from the allocator, reached through the window; the index stays inside its frame, and no Rust reference points into these frames. |
| `keep/src/arch/paging.rs` | `map_filled` | 1 | Copy a byte into a fresh frame | The frame is freshly allocated and owned by this mapping; the index is less than `data.len()`, which is at most a page. |
| `keep/src/arch/paging.rs` | `current` | 1 | Read CR3 | Reading CR3 has no side effects; the value is the live top-level table's address. |
| `keep/src/arch/paging.rs` | `activate` | 1 | Load CR3 | A user space from `new_user` shares the Keep's whole higher half, so the running code, stack and kernel data stay mapped across the switch. |
| `keep/src/arch/paging.rs` | `load_kernel_space` | 3 | Read RSP; load CR3; set CR4.PGE | Before CR3 is loaded the new tables are checked to map the running code, the stack, the descriptor tables, the interrupt stack and the screen as now. Global pages only change TLB behavior. |
| `keep/src/arch/pic.rs` | `disable` | 1 | Reprogram both 8259 PICs to vectors 0x20..0x2F and mask every line | The standard initialization sequence on the PICs' fixed ports, then a full mask; no memory effect. |
| `keep/src/arch/pit.rs` | `wait` | 2 | Start a one-shot count on PIT channel 2 and poll its output | Fixed PIT and port-B registers; the speaker stays off and nothing touches memory. |
| `keep/src/arch/port.rs` | `outb`, `outl`, `inb` | 6 | Port I/O instructions and the `unsafe fn` wrappers around them | `unsafe` because a port can reach a device that writes memory; each caller documents which device it talks to. |
| `keep/src/arch/qemu.rs` | `exit` | 1 | Write QEMU's debug-exit port | Only used in self-test mode under QEMU; elsewhere nothing decodes the port. |
| `keep/src/arch/serial.rs` | `init`, `write_byte` | 3 | Program and write COM1's 16550 registers | Standard UART registers at a fixed base; no memory effect. |
| `keep/src/arch/sync.rs` | `Exclusive` | 2 | `unsafe impl Sync`; hand out `&mut T` from an `UnsafeCell` | `with` sets a busy flag atomically before handing out the reference and clears it after, with interrupts off, so at most one reference exists at a time; `T: Send` lets the value move between tasks and interrupt handlers. |
| `keep/src/arch/task.rs` | `new_kernel`, `write_frame` | 2 | Write a new task's first frame and zero return address on its kernel stack | The slot is claimed atomically first, so nothing runs on that stack, which is mapped read-write; the writes are aligned and in its top bytes. |
| `keep/src/arch/task.rs` | `SyscallFrame` | 3 | Read the call number and arguments, and set the result, in the saved frame | The trap entry passed a frame on the current kernel stack, which stays in place until the syscall returns a frame to restore. |
| `keep/src/arch/task.rs` | `Context` | 3 | Read a task's message words, and deliver a message or a result, in its saved frame | The frame is on a task's kernel stack and lives as long as the task; the scheduler uses these only to move a message between two tasks' saved registers. |
| `keep/src/arch/vga.rs` | `put` | 1 | Volatile write to the text buffer | Row and column are bounds-checked, so the write stays inside the 80x25 buffer, mapped by the window. |
| `keep/src/arch/vga.rs` | `set_color` | 1 | Write one entry of the VGA DAC color table | Selects an entry and sets its red, green and blue; only changes how a color looks. |
| `keep/src/arch/vga.rs` | `hide_cursor` | 1 | Write the VGA CRT controller | Register 0x0A only turns the text cursor off. |
| `user/src/sys.rs` | `program!` | 1 | `#[unsafe(no_mangle)]` on the program's `_start` | The Keep starts the program by jumping to its ELF entry, which the linker places at `_start`. |
| `user/src/sys.rs` | `call` | 1 | `int 0x80` into the Keep | Enters the syscall gate; the Keep reads the registers, returns the result in rax and leaves the rest, and runs on its own stack. |
| `user/src/sys.rs` | `send`, `recv` | 2 | `int 0x80` to send or receive a message | As for `call`, but the message words travel in rsi, rdx, r10 and r8: send passes them in, recv takes them out. The Keep runs on its own stack and may run other tasks before returning. |
| `user/src/sys.rs` | `privilege_level` | 1 | Read CS | Reading CS has no side effects; the low two bits are the ring. |
| `user/src/sys.rs` | `crash` | 1 | `ud2` | Always raises an invalid-opcode fault; the Keep ends the task. Used only by the test program to show fault isolation. |

## Assembly

The doc allows assembly only for boot, task switching and interrupt
entry. The Keep has two `global_asm!` blocks; task switching happens in
the interrupt entry path, which restores whichever task's frame the
scheduler returns. Elsewhere, privileged instructions the compiler can't
emit (control-register and port access) are single `asm!` statements,
each an `unsafe` use listed above.

| File | What it does |
| --- | --- |
| `keep/src/arch/boot.rs` | Multiboot header; 32-bit entry that clears .bss, builds the boot page tables (identity and higher half), enables long mode, NX and paging, jumps to the higher half and calls `keep_entry` |
| `keep/src/arch/idt.rs` | The entry stubs (32 exceptions, the timer, yield, syscall and spurious) and the common save/restore path around `keep_trap`, which switches to the frame `keep_trap` returns |
