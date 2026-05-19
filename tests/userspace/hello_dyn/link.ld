/* Linker script for dynamically-linked userspace binaries.
 *
 * Produces an ET_DYN (PIE) executable with a PT_INTERP segment pointing
 * to /lib/ld-vibix.so. The kernel loads the interpreter at
 * INTERP_LOAD_BASE and transfers control to it.
 *
 * Base address 0x400000. SIZEOF_HEADERS at the start ensures the ELF
 * header and program-header table are included in the first LOAD segment,
 * making them available via AT_PHDR for the dynamic linker.
 *
 * No explicit PHDRS: the linker auto-generates PT_PHDR, PT_INTERP,
 * and PT_LOAD segments, which correctly covers the headers.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x0000000000400000 + SIZEOF_HEADERS;

    .interp : {
        *(.interp)
    }

    .text : {
        *(.text .text.*)
    }

    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
    }

    .rela.dyn : {
        *(.rela.dyn .rela.dyn.*)
        *(.rela.plt)
    }

    .dynsym : {
        *(.dynsym)
    }

    .dynstr : {
        *(.dynstr)
    }

    .hash : {
        *(.hash)
    }

    .gnu.hash : {
        *(.gnu.hash)
    }

    . = ALIGN(4096);

    .dynamic : {
        *(.dynamic)
    }

    .got : {
        *(.got .got.plt)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(COMMON)
        *(.bss .bss.*)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note.*)
        *(.comment)
    }
}
