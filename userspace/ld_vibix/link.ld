/* Linker script for ld-vibix.so — the vibix dynamic linker.
 *
 * Produces an ET_DYN (shared object) ELF loaded by the kernel at
 * INTERP_LOAD_BASE (0x4000_0000). The linker uses vaddr 0 as its
 * base so all addresses are offsets from the load base.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = SIZEOF_HEADERS;

    .text : {
        *(.text .text.*)
    }

    . = ALIGN(4096);

    .rodata : {
        *(.rodata .rodata.*)
    }

    .rela.dyn : {
        *(.rela.dyn .rela.dyn.*)
        *(.rela.plt .rela.plt.*)
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
