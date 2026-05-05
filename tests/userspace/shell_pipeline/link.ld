/* Linker script for the repro_fork userspace binary.
 *
 * Identical layout to `userspace/init/link.ld`: lower-half load base at
 * 0x400000, page-aligned PT_LOAD segments so the kernel's ELF loader can
 * map one page per page.  This binary is shipped in the ISO in place of
 * `userspace_init.elf` when the xtask `repro-fork` subcommand is used;
 * the kernel's loader is unchanged and sees what looks like a regular
 * PID-1 init image.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R+X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* R+W */
}

SECTIONS
{
    . = 0x0000000000400000;

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
        *(.got .got.plt)
    }
}
