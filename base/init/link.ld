/* Linker script for the userspace init binary (ring-3, lower half).
 *
 * Virtual base: 0x0000_0000_0040_0000 — the conventional ELF load
 * address for Linux/x86_64 static executables. All segments are in the
 * lower half of the address space so the kernel-loader's USER_ACCESSIBLE
 * PTE flag lets ring-3 code reach them. Segments are page-aligned to
 * 4 KiB so the kernel loader can map one page per page.
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
