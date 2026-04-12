//! Minimal ELF64 program-header walker.
//!
//! Scoped to what the kernel needs to map its own image: iterate
//! `PT_LOAD` segments and translate `p_flags` into `PageTableFlags`.
//! Deliberately hand-rolled rather than pulling in `xmas-elf` /
//! `goblin` — the structs are tiny and fixed, and a future userspace
//! ELF loader can grow this module instead of adding a second parser.

use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;

#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// One `PT_LOAD` segment of the kernel image, as the paging layer
/// wants it: a virtual range plus the `PageTableFlags` derived from
/// `p_flags` (`PF_W` → `WRITABLE`, no `PF_X` → `NO_EXECUTE`).
#[derive(Clone, Copy)]
pub(super) struct LoadSegment {
    pub vaddr: VirtAddr,
    pub memsz: u64,
    pub flags: PageTableFlags,
}

/// Iterate `PT_LOAD` segments of the running kernel's ELF image,
/// reachable through Limine's `ExecutableFileRequest`.
///
/// Panics with a clear message if the request response is missing,
/// the ELF magic is wrong, or the class isn't 64-bit — any of those
/// would mean the bootloader handed us something we can't reason
/// about, and limping on would only corrupt page tables.
pub(super) fn kernel_load_segments() -> impl Iterator<Item = LoadSegment> {
    let resp = crate::boot::KERNEL_FILE_REQUEST
        .get_response()
        .expect("Limine executable-file response missing");
    let file = resp.file();
    let base = file.addr();
    let size = file.size() as usize;
    assert!(
        size >= core::mem::size_of::<Elf64Ehdr>(),
        "kernel ELF too small for Ehdr"
    );

    // SAFETY: Limine guarantees the file bytes live at this address
    // for the lifetime of the kernel (BOOTLOADER_RECLAIMABLE-adjacent
    // but held through `EXECUTABLE_AND_MODULES`). We only read.
    let ehdr: &Elf64Ehdr = unsafe { &*(base as *const Elf64Ehdr) };
    assert_eq!(ehdr.e_ident[..4], ELF_MAGIC, "kernel ELF bad magic");
    assert_eq!(ehdr.e_ident[4], ELFCLASS64, "kernel ELF not ELFCLASS64");
    assert_eq!(
        ehdr.e_phentsize as usize,
        core::mem::size_of::<Elf64Phdr>(),
        "unexpected e_phentsize"
    );

    let phoff = ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phsz = ehdr.e_phentsize as usize;
    assert!(
        phoff + phnum * phsz <= size,
        "kernel ELF phdr table out of range"
    );

    // SAFETY: bounds checked above; the slice covers only phdrs.
    let phdrs: &[Elf64Phdr] =
        unsafe { core::slice::from_raw_parts(base.add(phoff) as *const Elf64Phdr, phnum) };

    phdrs.iter().filter_map(|ph| {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            return None;
        }
        let mut flags = PageTableFlags::PRESENT;
        if ph.p_flags & PF_W != 0 {
            flags |= PageTableFlags::WRITABLE;
        }
        if ph.p_flags & PF_X == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        Some(LoadSegment {
            vaddr: VirtAddr::new(ph.p_vaddr),
            memsz: ph.p_memsz,
            flags,
        })
    })
}
