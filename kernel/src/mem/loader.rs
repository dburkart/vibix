//! Minimal ELF64 image loader.
//!
//! Walks `PT_LOAD` segments of an ELF payload, allocates and maps 4 KiB
//! pages at each segment's `p_vaddr`, and copies `p_filesz` bytes from
//! the source image (zero-filling `p_memsz - p_filesz` for .bss). The
//! target range must land in the **upper half** of the virtual address
//! space so the mapping lands in PML4 slots 256-511, which are shared
//! across every task PML4 that `new_task_pml4` constructs. The loader
//! must therefore run before `task::init()`; later-spawned tasks will
//! inherit the mapping automatically.
//!
//! Scope: enough to prove end-to-end control transfer into a separately
//! linked ELF image. No ring-3, no per-process address spaces, no user
//! stack allocation — the entry is called at ring-0 with the kernel's
//! current stack still active.
//!
//! The loader writes segment contents through the HHDM window rather
//! than through the just-installed PTE, so the final mapping flags can
//! be applied at map time (e.g. read-only .text) without a separate
//! read-only → writable → read-only dance.

use x86_64::structures::paging::{Page, Size4KiB};
use x86_64::VirtAddr;

use super::elf;
use super::paging;

const PAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    NotElf64,
    NonCanonicalEntry,
    SegmentNotUpperHalf,
    SegmentNotPageAligned,
    SegmentFileTooShort,
    MapFailed,
}

/// Result of a successful load: the entry point and the number of
/// `PT_LOAD` segments that were mapped.
#[derive(Debug, Clone, Copy)]
pub struct LoadedImage {
    pub entry: VirtAddr,
    pub segments: usize,
}

/// Parse `bytes` as an ELF64 image and install its `PT_LOAD` segments
/// into the active page tables. Returns the entry point so the caller
/// can jump into it once the kernel is otherwise ready.
pub fn load(bytes: &[u8]) -> Result<LoadedImage, LoadError> {
    let parsed = elf::try_parse_elf64(bytes).ok_or(LoadError::NotElf64)?;

    let entry = parsed.entry();
    // Upper-half check: PML4 slots 256-511 are the shared kernel half.
    // A canonical upper-half address has bit 63 set.
    if (entry.as_u64() >> 63) != 1 {
        return Err(LoadError::SegmentNotUpperHalf);
    }

    let mut segments = 0usize;
    for seg in parsed.load_segments() {
        map_segment(bytes, seg)?;
        segments += 1;
    }

    Ok(LoadedImage { entry, segments })
}

fn map_segment(bytes: &[u8], seg: elf::LoadSegment) -> Result<(), LoadError> {
    if (seg.vaddr.as_u64() >> 63) != 1 {
        return Err(LoadError::SegmentNotUpperHalf);
    }
    if seg.vaddr.as_u64() & (PAGE_SIZE - 1) != 0 {
        return Err(LoadError::SegmentNotPageAligned);
    }

    let file_end = seg
        .file_offset
        .checked_add(seg.filesz)
        .ok_or(LoadError::SegmentFileTooShort)?;
    if (file_end as usize) > bytes.len() {
        return Err(LoadError::SegmentFileTooShort);
    }
    let src = &bytes[seg.file_offset as usize..file_end as usize];

    let page_count = seg.memsz.div_ceil(PAGE_SIZE);
    let hhdm = paging::hhdm_offset();

    for i in 0..page_count {
        let va = seg.vaddr + i * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(va);
        let frame = paging::map(page, seg.flags).map_err(|_| LoadError::MapFailed)?;

        // Fill this page through the HHDM window. The frame allocator
        // doesn't zero its output, so we clear the whole page first
        // (covers .bss tail and any slack past filesz), then overlay
        // the file bytes that fall inside this page.
        let dst_base = hhdm + frame.start_address().as_u64();
        // SAFETY: `frame` was just allocated by `paging::map` for our
        // exclusive use and is reachable writable via the HHDM window.
        unsafe {
            core::ptr::write_bytes(dst_base.as_mut_ptr::<u8>(), 0, PAGE_SIZE as usize);
        }

        let offset_in_seg = i * PAGE_SIZE;
        if offset_in_seg < seg.filesz {
            let copy_off = offset_in_seg as usize;
            let remaining = (seg.filesz - offset_in_seg) as usize;
            let n = remaining.min(PAGE_SIZE as usize);
            // SAFETY: same HHDM frame as the zero-fill above. `n` is
            // clamped to stay inside one page, and `src[copy_off..]` is
            // bounded by `filesz` which the caller checked against
            // `bytes.len()`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(copy_off),
                    dst_base.as_mut_ptr::<u8>(),
                    n,
                );
            }
        }
    }

    Ok(())
}
