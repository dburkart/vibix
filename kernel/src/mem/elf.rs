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
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
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
pub(crate) struct LoadSegment {
    pub vaddr: VirtAddr,
    pub memsz: u64,
    pub filesz: u64,
    pub file_offset: u64,
    pub flags: PageTableFlags,
}

/// Parsed ELF64 image metadata for segment walking.
#[derive(Clone, Copy)]
pub(crate) struct ParsedElf<'a> {
    ehdr: Elf64Ehdr,
    phdr_bytes: &'a [u8],
    phnum: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ElfParseError {
    TooSmallEhdr,
    BadMagic,
    NotElfClass64,
    UnexpectedPhEntSize,
    PhdrTableSizeOverflow,
    PhdrTableOutOfRange,
    NonCanonicalEntry,
    NonCanonicalLoadVaddr,
    LoadFileszExceedsMemsz,
    LoadFileRangeOverflow,
    LoadFileRangeOutOfRange,
    LoadVaddrRangeOverflow,
    EntryOutsideLoadSegment,
}

impl ElfParseError {
    const fn message(self) -> &'static str {
        match self {
            Self::TooSmallEhdr => "ELF too small for Ehdr",
            Self::BadMagic => "ELF bad magic",
            Self::NotElfClass64 => "ELF not ELFCLASS64",
            Self::UnexpectedPhEntSize => "unexpected e_phentsize",
            Self::PhdrTableSizeOverflow => "ELF phdr table size overflow",
            Self::PhdrTableOutOfRange => "ELF phdr table out of range",
            Self::NonCanonicalEntry => "ELF entry address is non-canonical",
            Self::NonCanonicalLoadVaddr => "ELF PT_LOAD virtual address is non-canonical",
            Self::LoadFileszExceedsMemsz => "ELF PT_LOAD p_filesz exceeds p_memsz",
            Self::LoadFileRangeOverflow => "ELF PT_LOAD file range arithmetic overflow",
            Self::LoadFileRangeOutOfRange => "ELF PT_LOAD file range exceeds image bounds",
            Self::LoadVaddrRangeOverflow => "ELF PT_LOAD virtual range arithmetic overflow",
            Self::EntryOutsideLoadSegment => "ELF entry address not covered by any PT_LOAD",
        }
    }
}

pub(crate) struct LoadSegmentIter<'a> {
    phdr_bytes: &'a [u8],
    phnum: usize,
    idx: usize,
}

impl<'a> Iterator for LoadSegmentIter<'a> {
    type Item = LoadSegment;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.phnum {
            let off = self.idx * core::mem::size_of::<Elf64Phdr>();
            self.idx += 1;
            // SAFETY: `phdr_bytes` was bounds-checked to hold exactly
            // `phnum` contiguous `Elf64Phdr` records. Unaligned reads
            // are intentional because ELF headers are byte-packed.
            let ph = unsafe {
                core::ptr::read_unaligned(self.phdr_bytes.as_ptr().add(off).cast::<Elf64Phdr>())
            };
            if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
                continue;
            }
            let mut flags = PageTableFlags::PRESENT;
            if ph.p_flags & PF_W != 0 {
                flags |= PageTableFlags::WRITABLE;
            }
            if ph.p_flags & PF_X == 0 {
                flags |= PageTableFlags::NO_EXECUTE;
            }
            return Some(LoadSegment {
                vaddr: VirtAddr::new(ph.p_vaddr),
                memsz: ph.p_memsz,
                filesz: ph.p_filesz,
                file_offset: ph.p_offset,
                flags,
            });
        }
        None
    }
}

impl<'a> ParsedElf<'a> {
    pub(crate) fn load_segments(self) -> LoadSegmentIter<'a> {
        LoadSegmentIter {
            phdr_bytes: self.phdr_bytes,
            phnum: self.phnum,
            idx: 0,
        }
    }

    pub(crate) fn entry(&self) -> VirtAddr {
        VirtAddr::new(self.ehdr.e_entry)
    }
}

/// Iterate `PT_LOAD` segments of the running kernel's ELF image,
/// reachable through Limine's `ExecutableFileRequest`.
///
/// Panics with a clear message if the request response is missing,
/// the ELF magic is wrong, or the class isn't 64-bit — any of those
/// would mean the bootloader handed us something we can't reason
/// about, and limping on would only corrupt page tables.
#[cfg(target_os = "none")]
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
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(base, size) };
    parse_elf64(bytes).load_segments()
}

#[cfg(target_os = "none")]
pub(crate) fn first_loaded_module_bytes() -> Option<&'static [u8]> {
    let resp = crate::boot::MODULE_REQUEST.get_response()?;
    let file = resp
        .modules()
        .iter()
        .find(|f| f.path().to_bytes().ends_with(b"/boot/userspace_hello.elf"))?;
    let base = file.addr();
    let size = file.size() as usize;
    // SAFETY: Limine places module payloads in EXECUTABLE_AND_MODULES
    // memory, which is preserved across `reclaim_bootloader_memory()`.
    // The slice stays valid for the rest of the kernel's lifetime.
    Some(unsafe { core::slice::from_raw_parts(base, size) })
}

#[cfg(target_os = "none")]
pub(crate) fn first_loaded_module_elf_summary() -> Option<(VirtAddr, usize)> {
    let resp = crate::boot::MODULE_REQUEST.get_response()?;
    let file = resp
        .modules()
        .iter()
        .find(|f| f.path().to_bytes().ends_with(b"/boot/userspace_hello.elf"))?;
    let base = file.addr();
    let size = file.size() as usize;
    if size < core::mem::size_of::<Elf64Ehdr>() {
        return None;
    }
    // SAFETY: Limine's module bytes are readable while its response
    // metadata is still live (before reclaim_bootloader_memory()).
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(base, size) };
    let parsed = try_parse_elf64(bytes)?;
    Some((parsed.entry(), parsed.load_segments().count()))
}

pub(crate) fn try_parse_elf64(bytes: &[u8]) -> Option<ParsedElf<'_>> {
    parse_elf64_inner(bytes).ok()
}

pub(crate) fn parse_elf64(bytes: &[u8]) -> ParsedElf<'_> {
    parse_elf64_inner(bytes).unwrap_or_else(|err| panic!("{}", err.message()))
}

fn parse_elf64_inner(bytes: &[u8]) -> Result<ParsedElf<'_>, ElfParseError> {
    if bytes.len() < core::mem::size_of::<Elf64Ehdr>() {
        return Err(ElfParseError::TooSmallEhdr);
    }

    // SAFETY: length checked above and we use `read_unaligned` so no
    // alignment assumptions are required for the input slice.
    let ehdr = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<Elf64Ehdr>()) };
    if ehdr.e_ident[..4] != ELF_MAGIC {
        return Err(ElfParseError::BadMagic);
    }
    if ehdr.e_ident[4] != ELFCLASS64 {
        return Err(ElfParseError::NotElfClass64);
    }
    if ehdr.e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
        return Err(ElfParseError::UnexpectedPhEntSize);
    }

    let phoff = ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phsz = ehdr.e_phentsize as usize;
    let phdr_table_end = phnum
        .checked_mul(phsz)
        .and_then(|n| phoff.checked_add(n))
        .ok_or(ElfParseError::PhdrTableSizeOverflow)?;
    if phdr_table_end > bytes.len() {
        return Err(ElfParseError::PhdrTableOutOfRange);
    }
    if VirtAddr::try_new(ehdr.e_entry).is_err() {
        return Err(ElfParseError::NonCanonicalEntry);
    }

    let mut entry_covered = false;
    for i in 0..phnum {
        let off = phoff + i * phsz;
        // SAFETY: `phdr_table_end` bounds-check above guarantees every
        // header read in this loop stays within `bytes`.
        let ph = unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(off).cast::<Elf64Phdr>()) };
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        if VirtAddr::try_new(ph.p_vaddr).is_err() {
            return Err(ElfParseError::NonCanonicalLoadVaddr);
        }
        if ph.p_filesz > ph.p_memsz {
            return Err(ElfParseError::LoadFileszExceedsMemsz);
        }
        let file_end = ph
            .p_offset
            .checked_add(ph.p_filesz)
            .ok_or(ElfParseError::LoadFileRangeOverflow)?;
        if file_end > bytes.len() as u64 {
            return Err(ElfParseError::LoadFileRangeOutOfRange);
        }
        let vaddr_end = ph
            .p_vaddr
            .checked_add(ph.p_memsz)
            .ok_or(ElfParseError::LoadVaddrRangeOverflow)?;
        if ehdr.e_entry >= ph.p_vaddr && ehdr.e_entry < vaddr_end {
            entry_covered = true;
        }
    }
    if !entry_covered {
        return Err(ElfParseError::EntryOutsideLoadSegment);
    }

    Ok(ParsedElf {
        ehdr,
        phdr_bytes: &bytes[phoff..phdr_table_end],
        phnum,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_elf64, try_parse_elf64};
    use x86_64::structures::paging::PageTableFlags;

    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;

    fn put16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn sample_elf_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; EHDR_SIZE + (2 * PHDR_SIZE)];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // little-endian
        bytes[6] = 1; // ELF v1
        put16(&mut bytes, 16, 2); // ET_EXEC
        put16(&mut bytes, 18, 0x3e); // x86_64
        put32(&mut bytes, 20, 1); // EV_CURRENT
        put64(&mut bytes, 24, 0x400080); // entry
        put64(&mut bytes, 32, EHDR_SIZE as u64); // e_phoff
        put16(&mut bytes, 52, EHDR_SIZE as u16); // e_ehsize
        put16(&mut bytes, 54, PHDR_SIZE as u16); // e_phentsize
        put16(&mut bytes, 56, 2); // e_phnum

        // phdr 0: RX text-like
        let p0 = EHDR_SIZE;
        put32(&mut bytes, p0, 1); // PT_LOAD
        put32(&mut bytes, p0 + 4, 1); // PF_X
        put64(&mut bytes, p0 + 16, 0x400000); // p_vaddr
        put64(&mut bytes, p0 + 40, 0x2000); // p_memsz

        // phdr 1: RW data-like
        let p1 = EHDR_SIZE + PHDR_SIZE;
        put32(&mut bytes, p1, 1); // PT_LOAD
        put32(&mut bytes, p1 + 4, 2); // PF_W
        put64(&mut bytes, p1 + 16, 0x402000); // p_vaddr
        put64(&mut bytes, p1 + 40, 0x1000); // p_memsz

        bytes
    }

    #[test]
    fn parses_entry_and_segment_flags() {
        let bytes = sample_elf_bytes();
        let parsed = parse_elf64(&bytes);
        assert_eq!(parsed.entry().as_u64(), 0x400080);
        let segs: Vec<_> = parsed.load_segments().collect();
        assert_eq!(segs.len(), 2);

        assert_eq!(segs[0].vaddr.as_u64(), 0x400000);
        assert_eq!(segs[0].memsz, 0x2000);
        assert!(!segs[0].flags.contains(PageTableFlags::WRITABLE));
        assert!(!segs[0].flags.contains(PageTableFlags::NO_EXECUTE));

        assert_eq!(segs[1].vaddr.as_u64(), 0x402000);
        assert_eq!(segs[1].memsz, 0x1000);
        assert!(segs[1].flags.contains(PageTableFlags::WRITABLE));
        assert!(segs[1].flags.contains(PageTableFlags::NO_EXECUTE));
    }

    #[test]
    #[should_panic(expected = "ELF bad magic")]
    fn rejects_bad_magic() {
        let mut bytes = sample_elf_bytes();
        bytes[0] = 0;
        let _ = parse_elf64(&bytes);
    }

    #[test]
    fn try_parse_rejects_bad_magic() {
        let mut bytes = sample_elf_bytes();
        bytes[0] = 0;
        assert!(try_parse_elf64(&bytes).is_none());
    }

    #[test]
    fn try_parse_rejects_non_canonical_entry() {
        let mut bytes = sample_elf_bytes();
        put64(&mut bytes, 24, 0x0001_0000_0000_0000);
        assert!(try_parse_elf64(&bytes).is_none());
    }

    #[test]
    fn try_parse_rejects_non_canonical_load_vaddr() {
        let mut bytes = sample_elf_bytes();
        let p0 = EHDR_SIZE;
        put64(&mut bytes, p0 + 16, 0x0001_0000_0000_0000);
        assert!(try_parse_elf64(&bytes).is_none());
    }

    #[test]
    #[should_panic(expected = "ELF entry address is non-canonical")]
    fn parse_panics_non_canonical_entry() {
        let mut bytes = sample_elf_bytes();
        put64(&mut bytes, 24, 0x0001_0000_0000_0000);
        let _ = parse_elf64(&bytes);
    }
}
