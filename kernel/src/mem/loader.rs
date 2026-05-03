//! ELF64 image loader — demand-paged via file-backed VMAs.
//!
//! ## Kernel-image loader (`load`)
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
//! ## Userspace loader (`load_user_elf_with_vmas`) — RFC 0007 §Demand-paged execve
//!
//! Rewrites the eager copy model into file-backed VMAs with demand faulting:
//!
//! - For each `PT_LOAD` segment, the **file-backed prefix**
//!   `[p_offset .. p_offset + p_filesz)` (rounded to pages) is backed
//!   by a [`FileObject`] over a per-binary [`PageCache`], inserted as
//!   a `Share::Private` VMA at the page-aligned `p_vaddr`. Page reads
//!   are deferred to the page-fault handler's `VmObject::fault` dispatch.
//! - When `p_memsz > p_filesz`, a second `AnonObject`-backed
//!   `Share::Private` VMA covers the zero tail (`.bss`). This prevents
//!   file data from leaking into `.bss` (RFC 0007 §Tail-page zeroing,
//!   split-segment trick).
//! - No frames are eagerly allocated into the PML4. The first touch on
//!   `.text` triggers a page fault → `FileObject::fault` → `readpage`
//!   → install PTE. `.bss` faults produce a fresh zero-fill page via
//!   `AnonObject::fault`.
//!
//! The backing `AddressSpaceOps` implementation for the loader is
//! [`ElfBytesOps`], which reads from the in-memory `&'static [u8]`
//! slice of the Limine module. This is the same data path the eager
//! loader used to `memcpy` through the HHDM, but deferred to fault time.
//!
//! The loader writes segment contents through the HHDM window rather
//! than through the just-installed PTE, so the final mapping flags can
//! be applied at map time (e.g. read-only .text) without a separate
//! read-only → writable → read-only dance.

use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;

use alloc::sync::Arc;

use super::addrspace::USER_VA_END;
use super::elf::{self, TlsInfo};
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
    /// A `PT_LOAD` segment's page-aligned end lands at or past
    /// `USER_VA_END` (`0x0000_8000_0000_0000`). `LoadedImage::image_end`
    /// is eventually wrapped in `VirtAddr::new`, which panics on the
    /// first non-canonical lower-half address. Reject at load time so
    /// the panic can't be reached from a malformed user ELF.
    SegmentEndsAtUserVaEnd,
    /// The main ELF has a PT_INTERP segment naming an interpreter, but no
    /// Limine module with a matching path suffix was found and the
    /// interpreter could not be read from the mounted VFS either.
    InterpNotFound,
    /// The interpreter ELF named by PT_INTERP failed to parse or map.
    InterpLoadFailed,
}

/// Virtual base address where the dynamic interpreter (PT_INTERP) is loaded.
///
/// Chosen to be above the typical userspace binary load range (~0x400000) but
/// well below the stack top (~0x7FFF_F000). This is a fixed address; a future
/// ASLR implementation will randomize it.
pub const INTERP_LOAD_BASE: u64 = 0x4000_0000;

/// Result of a successful load: the entry point, segment count, and the
/// page-aligned virtual address one byte past the last `PT_LOAD` segment.
/// `image_end` is the natural place to start the heap (`brk_start`) after
/// the process image is loaded.
#[derive(Debug, Clone, Copy)]
pub struct LoadedImage {
    pub entry: VirtAddr,
    pub segments: usize,
    /// First page-aligned address after the last PT_LOAD segment.
    /// The `sys_brk` implementation uses this as the initial heap start.
    pub image_end: u64,
    /// Entry point of the dynamic interpreter (PT_INTERP), adjusted by
    /// `INTERP_LOAD_BASE`. `None` if the binary has no PT_INTERP segment.
    pub interp_entry: Option<VirtAddr>,
    /// Virtual base address at which the interpreter was loaded.
    /// `None` if the binary has no PT_INTERP segment.
    pub interp_base: Option<u64>,
    /// Virtual address of the main binary's program-header table (AT_PHDR).
    pub phdr_vaddr: u64,
    /// Number of program-header entries (AT_PHNUM).
    pub phdr_count: u16,
    /// Size of each program-header entry in bytes (AT_PHENT).
    pub phdr_entsize: u16,
    /// Static TLS segment layout extracted from PT_TLS, if present.
    /// Used to allocate the initial TLS block for the process.
    pub tls_info: Option<TlsInfo>,
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
    let mut image_end = 0u64;
    let mut flusher = Flusher::new_active();
    let mut err: Option<LoadError> = None;
    for seg in parsed.load_segments() {
        if let Err(e) = map_segment(bytes, seg, &mut flusher) {
            err = Some(e);
            break;
        }
        // Track the page-aligned end of the highest PT_LOAD segment.
        let seg_end = (seg.vaddr.as_u64() + seg.memsz + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if seg_end > image_end {
            image_end = seg_end;
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

    Ok(LoadedImage {
        entry,
        segments,
        image_end,
        interp_entry: None,
        interp_base: None,
        phdr_vaddr: 0,
        phdr_count: 0,
        phdr_entsize: 0,
        tls_info: parsed.tls_info(),
    })
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
pub fn load_user_elf(bytes: &[u8], pml4: PhysFrame<Size4KiB>) -> Result<LoadedImage, LoadError> {
    let parsed = elf::try_parse_elf64(bytes).ok_or(LoadError::NotElf64)?;

    let entry = parsed.entry();
    // Reject upper-half entries. Canonical upper-half: bit 63 set.
    if entry.as_u64() >= UPPER_HALF_START {
        return Err(LoadError::SegmentNotLowerHalf);
    }

    let mut segments = 0usize;
    let mut image_end = 0u64;
    let mut err: Option<LoadError> = None;
    let mut partial_pages = 0u64;
    for seg in parsed.load_segments() {
        let seg_end = (seg.vaddr.as_u64() + seg.memsz + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if seg_end >= USER_VA_END {
            err = Some(LoadError::SegmentEndsAtUserVaEnd);
            break;
        }
        if let Err((e, mapped)) = map_user_segment(bytes, seg, pml4, 0) {
            err = Some(e);
            partial_pages = mapped;
            break;
        }
        if seg_end > image_end {
            image_end = seg_end;
        }
        segments += 1;
    }
    // No Flusher needed here: map_in_pml4 flushes immediately when pml4
    // is the active PML4, and skips when it is not (we haven't switched
    // CR3 yet at load time). The CR3 write in init_ring3_entry provides
    // the definitive TLB flush before entering user code.
    if let Some(e) = err {
        // Release every leaf frame we installed in `pml4` before failing.
        // Without this, frames in completed segments and any partial
        // progress within the aborted segment would be leaked when the
        // caller drops the staged AddressSpace — Drop walks `self.vmas`,
        // which the `load_user_elf_with_vmas` caller hasn't populated
        // yet.
        unmap_partial_load(parsed, pml4, segments, partial_pages);
        return Err(e);
    }

    Ok(LoadedImage {
        entry,
        segments,
        image_end,
        interp_entry: None,
        interp_base: None,
        phdr_vaddr: parsed.phdr_vaddr(),
        phdr_count: parsed.phdr_count(),
        phdr_entsize: parsed.phdr_entsize(),
        tls_info: parsed.tls_info(),
    })
}

/// Unmap and free every leaf frame installed by a partial
/// [`load_user_elf`] run. `completed` is the number of PT_LOAD segments
/// that were fully mapped; `partial_pages` is the number of pages of
/// segment `completed` (0-indexed: the aborted segment) that had been
/// mapped before its error. Unmapping an already-unmapped page is a
/// no-op, matching the defensive pattern in `Drop for AddressSpace`.
#[cfg(target_os = "none")]
fn unmap_partial_load(
    parsed: elf::ParsedElf<'_>,
    pml4: PhysFrame<Size4KiB>,
    completed: usize,
    partial_pages: u64,
) {
    unmap_partial_load_at_base(parsed, pml4, 0, completed, partial_pages);
}

/// Like [`unmap_partial_load`] but with an explicit `base_offset` added to
/// each segment's `p_vaddr` before computing the virtual address to unmap.
/// Used to clean up a partially-mapped interpreter whose segments were loaded
/// at `INTERP_LOAD_BASE` rather than at their literal `p_vaddr` values.
#[cfg(target_os = "none")]
fn unmap_partial_load_at_base(
    parsed: elf::ParsedElf<'_>,
    pml4: PhysFrame<Size4KiB>,
    base_offset: u64,
    completed: usize,
    partial_pages: u64,
) {
    use x86_64::structures::paging::FrameDeallocator;
    let mut alloc = paging::KernelFrameAllocator;
    for (idx, seg) in parsed.load_segments().enumerate().take(completed + 1) {
        let pages = if idx < completed {
            seg.memsz.div_ceil(PAGE_SIZE)
        } else {
            partial_pages
        };
        for i in 0..pages {
            let va = VirtAddr::new(seg.vaddr.as_u64().wrapping_add(base_offset) + i * PAGE_SIZE);
            let page = Page::<Size4KiB>::containing_address(va);
            if let Ok(frame) = paging::unmap_in_pml4(pml4, page) {
                // SAFETY: frame was just unmapped from `pml4`; no other
                // mapping aliases it (the staged PML4 is not live and
                // the loader holds the sole PTE reference, set to 1 by
                // `KernelFrameAllocator::allocate_frame` via
                // `frame::alloc`).
                unsafe {
                    alloc.deallocate_frame(frame);
                }
            }
        }
    }
}

/// Load `bytes` as a lower-half ELF into `address_space` using
/// demand-paged, file-backed VMAs (RFC 0007 §Demand-paged execve).
///
/// For each `PT_LOAD` segment:
///
/// 1. **File-backed prefix** — the pages covering `[p_offset ..
///    p_offset + p_filesz)` (rounded to page boundaries) are backed by
///    a [`FileObject`] over a per-binary [`PageCache`]. No frames are
///    eagerly allocated; reads are deferred to the page-fault handler.
///
/// 2. **Zero tail** — when `p_memsz > p_filesz`, the page-aligned
///    remainder is backed by a fresh [`AnonObject`] (zero-fill on
///    demand). This prevents file data from leaking into `.bss`.
///
/// The `pml4` parameter is still accepted so callers that installed
/// frames before this function was demand-paged can continue to pass
/// it; this function does NOT eagerly install any PTEs — the PML4 is
/// untouched. The CR3 write in `init_ring3_entry` / `exec_atomic`
/// provides the definitive TLB flush before entering user code.
///
/// PT_INTERP is handled identically: the named interpreter is located
/// among the Limine modules by path suffix (fallback: read from the
/// mounted VFS), parsed, and loaded at `INTERP_LOAD_BASE` via the
/// same file-backed VMA approach.
#[cfg(target_os = "none")]
pub fn load_user_elf_with_vmas(
    bytes: &'static [u8],
    _pml4: PhysFrame<Size4KiB>,
    address_space: &mut super::addrspace::AddressSpace,
) -> Result<LoadedImage, LoadError> {
    let parsed = elf::try_parse_elf64(bytes).ok_or(LoadError::NotElf64)?;

    let entry = parsed.entry();
    if entry.as_u64() >= UPPER_HALF_START {
        return Err(LoadError::SegmentNotLowerHalf);
    }

    // Register file-backed + zero-tail VMAs for the main binary's PT_LOAD
    // segments. Returns `(segment_count, page_aligned_image_end)`.
    let (segments, image_end) = register_demand_vmas(bytes, parsed, 0, address_space)?;

    let mut image = LoadedImage {
        entry,
        segments,
        image_end,
        interp_entry: None,
        interp_base: None,
        phdr_vaddr: parsed.phdr_vaddr(),
        phdr_count: parsed.phdr_count(),
        phdr_entsize: parsed.phdr_entsize(),
        tls_info: parsed.tls_info(),
    };

    // Check for a dynamic interpreter (PT_INTERP). If present, resolve
    // the interpreter ELF and recursively load its PT_LOAD segments at
    // INTERP_LOAD_BASE via the same demand-paged approach, then transfer
    // initial PC to the interpreter.
    //
    // Resolution order:
    //   1. Limine boot modules (basename match) — works during early
    //      bootstrap when the VFS may not be mounted yet.
    //   2. VFS path walk (full PT_INTERP path against the mounted root
    //      filesystem) — the normal path for execve of dynamic binaries
    //      once the FS is up.
    if let Some(interp_path) = parsed.interp_path() {
        // Try Limine modules first (basename match).
        let interp_basename = interp_path
            .iter()
            .rposition(|&b| b == b'/')
            .map(|slash| &interp_path[slash + 1..])
            .unwrap_or(interp_path);
        let module_bytes: Option<&'static [u8]> = elf::module_bytes_for_path(interp_basename);

        // Fall back to reading the interpreter from the VFS. The Vec is
        // leaked to produce `&'static [u8]` because `register_demand_vmas`
        // builds a `PageCache` + `ElfBytesOps` that must outlive the
        // process (demand faults read from it). The leak is bounded by
        // the interpreter's file size and reclaimed only at process exit
        // (same lifetime as the Limine module path).
        let fs_bytes: Option<&'static [u8]> = if module_bytes.is_none() {
            read_interp_from_fs(interp_path).map(|v| &*v.leak())
        } else {
            None
        };

        let interp_bytes: &'static [u8] = match (module_bytes, fs_bytes) {
            (Some(m), _) => m,
            (None, Some(v)) => v,
            (None, None) => return Err(LoadError::InterpNotFound),
        };

        let interp_parsed =
            elf::try_parse_elf64(interp_bytes).ok_or(LoadError::InterpLoadFailed)?;

        register_demand_vmas(interp_bytes, interp_parsed, INTERP_LOAD_BASE, address_space)
            .map_err(|_| LoadError::InterpLoadFailed)?;

        let interp_entry_vaddr = interp_parsed.entry().as_u64() + INTERP_LOAD_BASE;
        image.interp_entry = Some(VirtAddr::new(interp_entry_vaddr));
        image.interp_base = Some(INTERP_LOAD_BASE);
    }

    Ok(image)
}

/// Attempt to read the interpreter ELF from the mounted VFS at the full
/// PT_INTERP path (e.g. `/lib/ld-musl-x86_64.so.1`). Returns `None` if the
/// VFS root is not yet mounted or the file does not exist.
///
/// The returned `Vec<u8>` is heap-allocated; the caller leaks it to get
/// `&'static [u8]` for the demand-paged `PageCache` / `ElfBytesOps`.
#[cfg(target_os = "none")]
fn read_interp_from_fs(interp_path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    // Guard: the VFS may not be mounted yet during early init bootstrap.
    crate::fs::vfs::root()?;
    match crate::shell::vfs_helpers::read_all(interp_path) {
        Ok(bytes) if !bytes.is_empty() => Some(bytes),
        _ => None,
    }
}

// --- register_demand_vmas: file-backed + zero-tail VMA registration -------

/// Monotonic counter for synthetic inode IDs — each invocation (main binary +
/// interpreter) gets a distinct InodeId so page caches are per-binary
/// (RFC 0007 §Inode-binding rule).
static NEXT_SYNTH_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Register file-backed + zero-tail VMAs for one ELF's `PT_LOAD`
/// segments into `aspace`. `elf_bytes` is the full in-memory ELF slice;
/// `base_offset` is `0` for the main binary and `INTERP_LOAD_BASE` for
/// the interpreter.
///
/// Returns `(segment_count, page_aligned_image_end)` on success.
#[cfg(target_os = "none")]
fn register_demand_vmas(
    elf_bytes: &'static [u8],
    parsed_elf: elf::ParsedElf<'_>,
    base_offset: u64,
    aspace: &mut super::addrspace::AddressSpace,
) -> Result<(usize, u64), LoadError> {
    use super::file_object::FileObject;
    use super::page_cache::{InodeId, PageCache};
    use super::vmatree::{Share, Vma};
    use super::vmobject::{AnonObject, VmObject};

    // Build a per-binary PageCache. The `ElfBytesOps` reads from the
    // in-memory Limine module; i_size is the full ELF file length so
    // every PT_LOAD file range is within bounds.
    let synth_ino = NEXT_SYNTH_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let inode_id = InodeId::new(0xE1F0_0000, synth_ino);
    let ops = Arc::new(ElfBytesOps::new(elf_bytes));
    let cache = Arc::new(PageCache::new(
        inode_id,
        elf_bytes.len() as u64,
        ops as Arc<dyn super::aops::AddressSpaceOps>,
    ));

    let mut segments = 0usize;
    let mut image_end = 0u64;

    for seg in parsed_elf.load_segments() {
        let effective_vaddr = seg
            .vaddr
            .as_u64()
            .checked_add(base_offset)
            .ok_or(LoadError::SegmentNotLowerHalf)?;
        if effective_vaddr >= UPPER_HALF_START {
            return Err(LoadError::SegmentNotLowerHalf);
        }
        let seg_end_unaligned = effective_vaddr
            .checked_add(seg.memsz)
            .ok_or(LoadError::SegmentNotLowerHalf)?;
        if seg_end_unaligned > UPPER_HALF_START {
            return Err(LoadError::SegmentNotLowerHalf);
        }
        let seg_end = (seg_end_unaligned + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if seg_end >= USER_VA_END {
            return Err(LoadError::SegmentEndsAtUserVaEnd);
        }
        if effective_vaddr & (PAGE_SIZE - 1) != 0 {
            return Err(LoadError::SegmentNotPageAligned);
        }

        let prot_pte =
            (seg.flags | x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE).bits();

        // --- File-backed prefix VMA ---
        //
        // Covers `[effective_vaddr .. effective_vaddr + file_pages * PAGE_SIZE)`.
        // The `file_offset_pages` points into the cache at the page-aligned
        // start of `p_offset`, and `len_pages` is the page-aligned file size.
        let file_pages = seg.filesz.div_ceil(PAGE_SIZE) as usize;
        if file_pages > 0 {
            let file_offset_pages = seg.file_offset / PAGE_SIZE;
            let file_obj = FileObject::new(
                cache.clone(),
                file_offset_pages,
                file_pages,
                Share::Private,
                0o2,  // O_RDWR snapshot — the loader has full access
                true, // exec_allowed — loader is mapping an executable
            );
            let file_start = effective_vaddr as usize;
            let file_end = file_start + file_pages * PAGE_SIZE as usize;
            let file_vma = Vma::new(
                file_start,
                file_end,
                0x3,
                prot_pte,
                Share::Private,
                file_obj as Arc<dyn VmObject>,
                0,
            );
            aspace.insert(file_vma);
        }

        // --- Zero-tail (.bss) VMA ---
        //
        // When `p_memsz > p_filesz`, the remaining pages are zero-fill.
        // This is the `.bss` section (or alignment padding). Backed by
        // an `AnonObject` so the first fault returns a zeroed page.
        let total_pages = seg.memsz.div_ceil(PAGE_SIZE) as usize;
        if total_pages > file_pages {
            let bss_page_count = total_pages - file_pages;
            let bss_start = effective_vaddr as usize + file_pages * PAGE_SIZE as usize;
            let bss_end = bss_start + bss_page_count * PAGE_SIZE as usize;
            let bss_obj = AnonObject::new(Some(bss_page_count));
            let bss_vma = Vma::new(
                bss_start,
                bss_end,
                0x3,
                prot_pte,
                Share::Private,
                bss_obj as Arc<dyn VmObject>,
                0,
            );
            aspace.insert(bss_vma);
        }

        if seg_end > image_end {
            image_end = seg_end;
        }
        segments += 1;
    }
    Ok((segments, image_end))
}

// --- ElfBytesOps: AddressSpaceOps for in-memory ELF module bytes ----------

/// `AddressSpaceOps` implementation that reads from an in-memory
/// `&'static [u8]` ELF module slice. Used by the demand-paged ELF
/// loader to serve `readpage` requests from the Limine module's bytes.
///
/// On `readpage(pgoff, buf)`, the implementation copies up to 4 KiB
/// from `bytes[pgoff * 4096 ..]` into `buf`, zero-filling the tail
/// past `bytes.len()` (RFC 0007 §Tail-page zeroing — no stale frame
/// data leaks into userspace).
struct ElfBytesOps {
    bytes: &'static [u8],
}

impl ElfBytesOps {
    fn new(bytes: &'static [u8]) -> Self {
        Self { bytes }
    }
}

impl super::aops::AddressSpaceOps for ElfBytesOps {
    fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64> {
        crate::debug_lockdep::assert_no_spinlocks_held("ElfBytesOps::readpage");

        let start = (pgoff as usize).saturating_mul(PAGE_SIZE as usize);
        if start >= self.bytes.len() {
            // Entirely past EOF — zero-fill.
            buf.fill(0);
            return Ok(0);
        }
        let end = core::cmp::min(start + PAGE_SIZE as usize, self.bytes.len());
        let n = end - start;
        buf[..n].copy_from_slice(&self.bytes[start..end]);
        if n < PAGE_SIZE as usize {
            buf[n..].fill(0);
        }
        Ok(n)
    }

    fn writepage(&self, _pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
        crate::debug_lockdep::assert_no_spinlocks_held("ElfBytesOps::writepage");
        // The ELF loader's PageCache is never dirty — all segments are
        // Private (CoW) and the in-memory module is read-only.
        Err(crate::fs::EROFS)
    }
}

/// On error, returns the underlying `LoadError` along with the number of
/// pages that had been successfully mapped into `pml4` before the error —
/// the caller uses that count to unmap and free those frames on the
/// failure path.
///
/// `base_offset` is added to each segment's `p_vaddr` before mapping. Pass
/// `0` for the main binary (which is linked at its final load address) and
/// `INTERP_LOAD_BASE` for a position-independent interpreter whose segment
/// vaddrs start near 0.
fn map_user_segment(
    bytes: &[u8],
    seg: elf::LoadSegment,
    pml4: PhysFrame<Size4KiB>,
    base_offset: u64,
) -> Result<(), (LoadError, u64)> {
    let effective_vaddr = seg
        .vaddr
        .as_u64()
        .checked_add(base_offset)
        .ok_or((LoadError::SegmentNotLowerHalf, 0))?;
    if effective_vaddr >= UPPER_HALF_START {
        return Err((LoadError::SegmentNotLowerHalf, 0));
    }
    // Reject segments whose virtual range overflows or crosses the
    // lower-half ceiling. Without this check, a large `p_memsz` could
    // push later pages into non-canonical space, panicking in
    // `VirtAddr::new()` during the mapping loop.
    if effective_vaddr
        .checked_add(seg.memsz)
        .map_or(true, |end| end > UPPER_HALF_START)
    {
        return Err((LoadError::SegmentNotLowerHalf, 0));
    }
    if effective_vaddr & (PAGE_SIZE - 1) != 0 {
        return Err((LoadError::SegmentNotPageAligned, 0));
    }

    let file_end = seg.file_offset + seg.filesz;
    let src = &bytes[seg.file_offset as usize..file_end as usize];

    let page_count = seg.memsz.div_ceil(PAGE_SIZE);
    let hhdm = paging::hhdm_offset();

    // Add USER_ACCESSIBLE to every flag set derived from the ELF flags so
    // ring-3 code can actually reach the pages.
    let flags = seg.flags | PageTableFlags::USER_ACCESSIBLE;

    let mut mapped = 0u64;
    for i in 0..page_count {
        let va = VirtAddr::new(effective_vaddr + i * PAGE_SIZE);
        let page = Page::<Size4KiB>::containing_address(va);
        // map_in_pml4 allocates a fresh zeroed frame and installs it in
        // pml4 (not the global kernel mapper).
        let frame = match paging::map_in_pml4(pml4, page, flags) {
            Ok(f) => f,
            Err(e) => return Err((LoadError::MapFailed(e), mapped)),
        };
        mapped += 1;

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
