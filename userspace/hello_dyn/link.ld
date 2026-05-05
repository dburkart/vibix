/* Linker script for dynamically-linked userspace binaries.
 *
 * Produces an ET_DYN (PIE) executable with a PT_INTERP segment pointing
 * to /lib/ld-vibix.so. The kernel loads the interpreter at
 * INTERP_LOAD_BASE and transfers control to it.
 *
 * Base address 0x400000 matches static executables. The binary still
 * contains relocations (.rela.dyn) that the dynamic linker processes.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    interp PT_INTERP FLAGS(4);  /* R */
    text   PT_LOAD FLAGS(5);    /* R+X */
    rodata PT_LOAD FLAGS(4);    /* R   */
    data   PT_LOAD FLAGS(6);    /* R+W */
    dynamic PT_DYNAMIC FLAGS(6); /* R+W */
}

SECTIONS
{
    . = 0x0000000000400000;

    .interp : {
        *(.interp)
    } :interp :text

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    .rela.dyn : {
        *(.rela.dyn .rela.dyn.*)
        *(.rela.plt)
    } :rodata

    .dynsym : {
        *(.dynsym)
    } :rodata

    .dynstr : {
        *(.dynstr)
    } :rodata

    .hash : {
        *(.hash)
    } :rodata

    .gnu.hash : {
        *(.gnu.hash)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .dynamic : {
        *(.dynamic)
    } :data :dynamic

    .got : {
        *(.got .got.plt)
    } :data

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
    }
}
