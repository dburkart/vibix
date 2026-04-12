/* vibix higher-half kernel linker script (Limine Boot Protocol rev 3). */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    limine_requests PT_LOAD;
    text            PT_LOAD;
    rodata          PT_LOAD;
    data            PT_LOAD;
    dynamic         PT_DYNAMIC;
}

SECTIONS
{
    /* Top 2 GiB of virtual address space: -2 GiB. Matches code-model=kernel. */
    . = 0xffffffff80000000;

    .limine_requests : {
        PROVIDE(__limine_requests_start = .);
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
        PROVIDE(__limine_requests_end = .);
    } :limine_requests

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .text : {
        PROVIDE(__text_start = .);
        *(.text .text.*)
        PROVIDE(__text_end = .);
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        PROVIDE(__rodata_start = .);
        *(.rodata .rodata.*)
        PROVIDE(__rodata_end = .);
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        PROVIDE(__data_start = .);
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
        PROVIDE(__data_end = .);
    } :data

    .dynamic : {
        *(.dynamic)
    } :data :dynamic

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
    }
}
