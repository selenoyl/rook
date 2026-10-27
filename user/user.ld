/* A Rook user program runs at 4 MiB, in three segments, each on pages of
 * its own so the Keep can map each with exactly the access it needs:
 * code read+execute, constants read-only, data read+write. Nothing is
 * both writable and executable; the Keep refuses a program that asks. */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);  /* read, execute */
    rodata PT_LOAD FLAGS(4);  /* read */
    data   PT_LOAD FLAGS(6);  /* read, write */
}

SECTIONS
{
    . = 0x400000;
    .text : { *(.text .text.*) } :text

    . = ALIGN(4K);
    .rodata : { *(.rodata .rodata.*) } :rodata

    . = ALIGN(4K);
    .data : { *(.data .data.*) *(.got .got.*) } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.comment)
        *(.note .note.*)
    }
}
