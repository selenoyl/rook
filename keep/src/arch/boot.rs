//! Boot: the Multiboot header, the switch from 32-bit protected mode to
//! 64-bit long mode, and the jump into Rust in the higher half.
//!
//! The loader (QEMU's `-kernel`, or GRUB) puts the flat image at 1 MiB
//! and jumps to `_start` in 32-bit protected mode with paging off, EAX
//! holding the Multiboot magic and EBX the address of its information
//! block. This code works with physical addresses only: it clears .bss,
//! maps the first GiB twice with 2 MiB pages (at its physical address,
//! and at KERNEL_BASE where the rest of the Keep is linked), turns on long
//! mode, no-execute and paging, then jumps up to `keep_start` and calls
//! `keep_entry` on the guarded 64 KiB boot stack.

use core::arch::global_asm;

global_asm!(
    // Multiboot (version 1) header. Flags: page-align modules, provide a
    // memory map, and use the address fields below (the image is a flat
    // binary, not an ELF file).
    ".section .multiboot, \"a\"",
    ".balign 4",
    "multiboot_header:",
    ".long 0x1BADB002",
    ".long 0x00010003",
    ".long -(0x1BADB002 + 0x00010003)",
    ".long multiboot_header",  // header_addr
    ".long __keep_phys_start", // load_addr
    ".long __load_end_phys",   // load_end_addr
    ".long __bss_end_phys",    // bss_end_addr
    ".long _start",            // entry_addr
    "",
    ".section .boot.text, \"ax\"",
    ".code32",
    ".global _start",
    "_start:",
    "    cli",
    "    mov ebp, eax", // Multiboot magic
    "    mov esi, ebx", // Multiboot information address
    // Clear .bss, which also clears the boot page tables and stack.
    "    mov edi, offset __load_end_phys",
    "    mov ecx, offset __bss_end_phys",
    "    sub ecx, edi",
    "    xor eax, eax",
    "    cld",
    "    rep stosb",
    "    mov esp, offset boot_stack_top_phys",
    // Long mode needs CPUID leaf 0x80000001, EDX bit 29.
    "    mov eax, 0x80000000",
    "    cpuid",
    "    cmp eax, 0x80000001",
    "    jb .Lno_long_mode",
    "    mov eax, 0x80000001",
    "    cpuid",
    "    test edx, 0x20000000",
    "    jz .Lno_long_mode",
    // Page tables. One page directory maps 0..1 GiB with present,
    // writable 2 MiB pages; it is reachable at 0 (PML4[0] -> PDPT[0]) and
    // at KERNEL_BASE (PML4[511] -> PDPT[510]).
    "    mov eax, offset boot_pdpt_low_phys",
    "    or eax, 0x3",
    "    mov dword ptr [boot_pml4_phys], eax",
    "    mov eax, offset boot_pdpt_high_phys",
    "    or eax, 0x3",
    "    mov dword ptr [boot_pml4_phys + 511 * 8], eax",
    "    mov eax, offset boot_pd_phys",
    "    or eax, 0x3",
    "    mov dword ptr [boot_pdpt_low_phys], eax",
    "    mov dword ptr [boot_pdpt_high_phys + 510 * 8], eax",
    "    xor ecx, ecx",
    ".Lmap_page:",
    "    mov eax, ecx",
    "    shl eax, 21",
    "    or eax, 0x83",
    "    mov dword ptr [boot_pd_phys + ecx * 8], eax",
    "    inc ecx",
    "    cmp ecx, 512",
    "    jne .Lmap_page",
    "    mov eax, offset boot_pml4_phys",
    "    mov cr3, eax",
    "    mov eax, cr4",
    "    or eax, 0x20", // PAE
    "    mov cr4, eax",
    "    mov ecx, 0xC0000080", // EFER
    "    rdmsr",
    "    or eax, 0x900", // long mode enable, no-execute enable
    "    wrmsr",
    "    mov eax, cr0",
    "    or eax, 0x80010000", // paging, write protect
    "    mov cr0, eax",
    // Load a 64-bit GDT and far-return into 64-bit code.
    "    lgdt [boot_gdt_ptr]",
    "    mov eax, 0x08",
    "    push eax",
    "    mov eax, offset .Llong_mode",
    "    push eax",
    "    retf",
    ".Lno_long_mode:",
    // Not a 64-bit CPU: write \"No x64\" in white on red, then stop.
    "    mov dword ptr [0xB8000], 0x4F6F4F4E",
    "    mov dword ptr [0xB8004], 0x4F784F20",
    "    mov dword ptr [0xB8008], 0x4F344F36",
    ".Lhalt32:",
    "    hlt",
    "    jmp .Lhalt32",
    "",
    ".code64",
    ".Llong_mode:",
    // Still running at the physical address; jump up to the higher half.
    "    movabs rax, offset keep_start",
    "    jmp rax",
    "",
    ".section .boot.rodata, \"a\"",
    ".balign 8",
    "boot_gdt:",
    "    .quad 0",
    "    .quad 0x00AF9A000000FFFF", // 64-bit kernel code
    "    .quad 0x00CF92000000FFFF", // kernel data
    "boot_gdt_ptr:",
    "    .word boot_gdt_ptr - boot_gdt - 1",
    "    .long boot_gdt",
    "",
    ".section .text.keep_start, \"ax\"",
    "keep_start:",
    "    mov ax, 0x10",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ss, ax",
    "    xor eax, eax",
    "    mov fs, ax",
    "    mov gs, ax",
    "    mov rsp, offset boot_stack_top",
    "    mov edi, ebp", // magic, zero-extended into RDI
    "    mov esi, esi", // information address, zero-extended into RSI
    "    call keep_entry",
    ".Lhalt64:",
    "    cli",
    "    hlt",
    "    jmp .Lhalt64",
    "",
    ".section .bss.boot, \"aw\", @nobits",
    ".balign 4096",
    ".global boot_pml4",
    ".global boot_pdpt_low",
    ".global boot_pdpt_high",
    ".global boot_pd",
    "boot_pml4: .skip 4096",
    "boot_pdpt_low: .skip 4096",
    "boot_pdpt_high: .skip 4096",
    "boot_pd: .skip 4096",
    // The boot stack, with an unmapped guard page below it once the
    // Keep's own page tables are loaded.
    ".global boot_stack_guard",
    ".global boot_stack_top",
    "boot_stack_guard: .skip 4096",
    "boot_stack: .skip 65536",
    "boot_stack_top:",
);

/// First Rust code to run, called by the boot assembly in 64-bit mode.
/// The loader's information is copied out here, while the boot identity
/// map still reaches it.
#[unsafe(no_mangle)]
extern "C" fn keep_entry(magic: u32, info: u32) -> ! {
    super::serial::init();
    let raw = super::multiboot::read(magic, info);
    let boot = crate::bootinfo::BootInfo::parse(raw.mmap, raw.cmdline);
    crate::keep_main(raw.magic_ok, boot)
}
