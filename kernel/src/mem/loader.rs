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

use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;

use super::elf;
use super::paging;
use super::tlb::Flusher;

const PAGE_SIZE: u64 = 4096;

#[derive(Debug)]
pub enum LoadError {
    /// `bytes` failed ELF64 parsing (bad magic, wrong class, bad phdr
    /// table, non-canonical addresses, entry outside PT_LOAD, etc.).
    NotElf64,
    /// A `PT_LOAD` segment (or the entry) is in the lower half of the
    /// virtual address space. The kernel-image loader only installs
    /// upper-half mappings so they propagate through `new_task_pml4`.
    SegmentNotUpperHalf,
    /// A `PT_LOAD` segment (or the entry) is in the upper half of the
    /// virtual address space. The user-space loader only accepts lower-half
    /// addresses so pages go into the process's own PML4.
    SegmentNotLowerHalf,
    /// A `PT_LOAD` segment's `p_vaddr` isn't 4 KiB-aligned. We only
    /// install 4 KiB PTEs so the caller's linker script has to align
    /// segments to that boundary.
    SegmentNotPageAligned,
    /// Frame allocation or page-table install failed mid-segment.
    /// Wraps the underlying `paging::map` error so callers can tell
    /// `FrameAllocationFailed` from `PageAlreadyMapped` etc.
    MapFailed(MapToError<Size4KiB>),
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
    let mut flusher = Flusher::new_active();
    let mut err: Option<LoadError> = None;
    for seg in parsed.load_segments() {
        if let Err(e) = map_segment(bytes, seg, &mut flusher) {
            err = Some(e);
            break;
        }
        segments += 1;
    }
    // `finish` on every path: early-returning via `?` on `map_segment`
    // would drop the Flusher un-finished and trip its Drop-time panic,
    // turning a graceful `LoadError` into a kernel panic.
    flusher.finish();
    if let Some(e) = err {
        return Err(e);
    }

    Ok(LoadedImage { entry, segments })
}

/// First canonical upper-half address. Bits [63:47] must all be 1 for
/// a valid upper-half VA.
const UPPER_HALF_START: u64 = 0xFFFF_8000_0000_0000;

/// Load `bytes` as a lower-half ELF64 image (entry and all PT_LOAD
/// segments must be `< UPPER_HALF_START`) into the PML4 rooted at
/// `pml4`. Returns the entry point and the number of mapped segments.
///
/// Unlike [`load`], segments are installed with `USER_ACCESSIBLE` set so
/// ring-3 code can execute and read/write them. The mapping is installed
/// only in `pml4` — not in the shared kernel upper-half — so the pages
/// are exclusive to this process.
///
/// # Errors
///
/// Returns `LoadError::NotElf64` if parsing fails, and
/// `LoadError::SegmentNotLowerHalf` if any PT_LOAD or the entry point
/// is in the upper half.
pub fn load_user_elf(
    bytes: &[u8],
    pml4: PhysFrame<Size4KiB>,
) -> Result<LoadedImage, LoadError> {
    let parsed = elf::try_parse_elf64(bytes).ok_or(LoadError::NotElf64)?;

    let entry = parsed.entry();
    // Reject upper-half entries. Canonical upper-half: bit 63 set.
    if entry.as_u64() >= UPPER_HALF_START {
        return Err(LoadError::SegmentNotLowerHalf);
    }

    let mut segments = 0usize;
    let mut err: Option<LoadError> = None;
    for seg in parsed.load_segments() {
        if let Err(e) = map_user_segment(bytes, seg, pml4) {
            err = Some(e);
            break;
        }
        segments += 1;
    }
    // No Flusher needed here: map_in_pml4 flushes immediately when pml4
    // is the active PML4, and skips when it is not (we haven't switched
    // CR3 yet at load time). The CR3 write in init_ring3_entry provides
    // the definitive TLB flush before entering user code.
    if let Some(e) = err {
        return Err(e);
    }

    Ok(LoadedImage { entry, segments })
}

fn map_user_segment(
    bytes: &[u8],
    seg: elf::LoadSegment,
    pml4: PhysFrame<Size4KiB>,
) -> Result<(), LoadError> {
    if seg.vaddr.as_u64() >= UPPER_HALF_START {
        return Err(LoadError::SegmentNotLowerHalf);
    }
    if seg.vaddr.as_u64() & (PAGE_SIZE - 1) != 0 {
        return Err(LoadError::SegmentNotPageAligned);
    }

    let file_end = seg.file_offset + seg.filesz;
    let src = &bytes[seg.file_offset as usize..file_end as usize];

    let page_count = seg.memsz.div_ceil(PAGE_SIZE);
    let hhdm = paging::hhdm_offset();

    // Add USER_ACCESSIBLE to every flag set derived from the ELF flags so
    // ring-3 code can actually reach the pages.
    let flags = seg.flags | PageTableFlags::USER_ACCESSIBLE;

    for i in 0..page_count {
        let va = seg.vaddr + i * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(va);
        // map_in_pml4 allocates a fresh zeroed frame and installs it in
        // pml4 (not the global kernel mapper).
        let frame = paging::map_in_pml4(pml4, page, flags).map_err(LoadError::MapFailed)?;

        // Fill file content through the HHDM window.
        let dst_base = hhdm + frame.start_address().as_u64();
        // SAFETY: `frame` was just allocated exclusively for this segment
        // page, and the HHDM mapping gives us writable access to it.
        unsafe {
            // The frame is already zeroed by map_in_pml4, but we still
            // copy file bytes in to overlay the .bss tail.
            let offset_in_seg = i * PAGE_SIZE;
            if offset_in_seg < seg.filesz {
                let copy_off = offset_in_seg as usize;
                let remaining = (seg.filesz - offset_in_seg) as usize;
                let n = remaining.min(PAGE_SIZE as usize);
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

fn map_segment(
    bytes: &[u8],
    seg: elf::LoadSegment,
    flusher: &mut Flusher,
) -> Result<(), LoadError> {
    if (seg.vaddr.as_u64() >> 63) != 1 {
        return Err(LoadError::SegmentNotUpperHalf);
    }
    if seg.vaddr.as_u64() & (PAGE_SIZE - 1) != 0 {
        return Err(LoadError::SegmentNotPageAligned);
    }

    // The parser already rejects PT_LOAD segments where
    // `p_offset + p_filesz` overflows or exceeds the image, so this
    // slice is just a sanity restatement of that invariant.
    let file_end = seg.file_offset + seg.filesz;
    let src = &bytes[seg.file_offset as usize..file_end as usize];

    let page_count = seg.memsz.div_ceil(PAGE_SIZE);
    let hhdm = paging::hhdm_offset();

    for i in 0..page_count {
        let va = seg.vaddr + i * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(va);
        let frame = paging::map(page, seg.flags, flusher).map_err(LoadError::MapFailed)?;

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
