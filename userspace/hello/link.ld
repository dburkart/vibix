/* Linker script for the userspace hello ELF loaded by the kernel.
 *
 * Virtual base: 0xffff_ffff_c000_0000 — 1 GiB into the top 2 GiB kernel
 * region. The kernel itself lives at 0xffff_ffff_8000_0000 and is at
 * most a few megabytes, leaving the rest of the -2 GiB window free.
 * The range is canonical, falls within `code-model=kernel`'s ±2 GiB
 * reach, and sits in the upper half of the address space — upper-half
 * PML4 slots are shared by every task PML4 via paging::new_task_pml4,
 * so a mapping installed in the kernel PML4 before task::init() is
 * visible to any task that later runs this code.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD;
    rodata PT_LOAD;
    data   PT_LOAD;
}

SECTIONS
{
    . = 0xffffffffc0000000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note.*)
        *(.comment)
        *(.dynamic)
    }
}
