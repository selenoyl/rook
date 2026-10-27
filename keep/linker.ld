/* The Keep is loaded at 1 MiB physical and runs in the top 2 GiB of the
 * address space, at KERNEL_BASE + its physical address, where the
 * "kernel" code model expects it. Only the boot code, which runs before
 * paging, is linked at its physical address.
 *
 * The build turns this into a flat image starting at 1 MiB; the
 * Multiboot header at its start tells the loader where each part goes. */
ENTRY(_start)

KERNEL_BASE = 0xFFFFFFFF80000000;

SECTIONS
{
    . = 1M;
    __keep_phys_start = .;

    .boot : ALIGN(4K)
    {
        KEEP(*(.multiboot))
        *(.boot.text)
        *(.boot.rodata)
    }

    . = ALIGN(4K);
    . += KERNEL_BASE;

    .text : AT(ADDR(.text) - KERNEL_BASE)
    {
        __text_start = .;
        *(.text .text.*)
        . = ALIGN(4K);
        __text_end = .;
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_BASE)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        . = ALIGN(4K);
        __rodata_end = .;
    }

    .data : AT(ADDR(.data) - KERNEL_BASE)
    {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
    }
    __load_end_phys = . - KERNEL_BASE;

    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_BASE)
    {
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4K);
        __bss_end = .;
    }
    __bss_end_phys = __bss_end - KERNEL_BASE;
    __keep_phys_end = __bss_end_phys;

    /* Physical addresses of the boot page tables and stack, for the
     * 32-bit code that runs before paging. */
    boot_pml4_phys = boot_pml4 - KERNEL_BASE;
    boot_pdpt_low_phys = boot_pdpt_low - KERNEL_BASE;
    boot_pdpt_high_phys = boot_pdpt_high - KERNEL_BASE;
    boot_pd_phys = boot_pd - KERNEL_BASE;
    boot_stack_top_phys = boot_stack_top - KERNEL_BASE;

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.comment)
        *(.note .note.*)
    }
}
