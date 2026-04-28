/* Linker script for the pjdfstest no_std runner — issue #642.
 *
 * Identical layout to userspace/init/link.ld: lower-half ring-3 ELF
 * loaded at 0x400000 with R+X / R / R+W PT_LOADs page-aligned. The
 * kernel's loader maps each segment with USER_ACCESSIBLE bits, so
 * matching userspace_init's link map keeps the loader happy without
 * any new code paths.
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

    /* The runner stores function pointers inside the static `CASES`
     * table; under static reloc-model the compiler still emits
     * `call *<sym>(%rip)` against a `.got` slot for each pointer. We
     * keep `.got` / `.got.plt` in the read-only segment so those
     * loads resolve to real, fully-relocated entries instead of
     * NULL — discarding them (as `userspace_init` does) crashes the
     * runner on the first per-case dispatch with a #PF at `0x0`. */
    .got : {
        *(.got)
    } :rodata
    .got.plt : {
        *(.got.plt)
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
