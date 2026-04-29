//! Physical-frame allocator, kernel heap, and paging.
//!
//!  - `frame::BitmapFrameAllocator` tracks one bit per 4 KiB frame over
//!    Limine's USABLE regions and reclaims frames on `deallocate_frame`.
//!    Pure logic, no `limine`/`x86_64` dependencies → host-testable. A
//!    global instance is installed by `frame::init` and shared by the
//!    heap and the paging layer.
//!  - `heap` pulls one contiguous 1 MiB slice of frames from the global
//!    allocator and hands it to `linked_list_allocator::LockedHeap`.
//!  - `paging` wraps Limine's active PML4 in an `OffsetPageTable` so
//!    the kernel can own its own `map`/`unmap`/`translate` API.

#[cfg(any(target_os = "none", test))]
pub mod aops;
pub mod frame;
#[cfg(any(target_os = "none", test))]
pub mod page_cache;
pub mod refcount;
pub mod tlb;

#[cfg(any(target_os = "none", test))]
pub(crate) mod auxv;
#[cfg(any(target_os = "none", test))]
pub(crate) mod elf;
#[cfg(target_os = "none")]
pub mod heap;
#[cfg(target_os = "none")]
pub mod loader;
#[cfg(target_os = "none")]
pub mod paging;
#[cfg(target_os = "none")]
pub mod pat;
#[cfg(any(target_os = "none", test))]
pub mod vmatree;
#[cfg(any(target_os = "none", test))]
pub mod vmobject;

#[cfg(any(target_os = "none", test))]
pub mod pf;

#[cfg(any(target_os = "none", test))]
pub mod addrspace;

#[cfg(target_os = "none")]
use spin::Once;

/// Total bytes of USABLE physical memory reported by Limine, snapshotted
/// before the memmap response's backing storage can be reclaimed. Surfaced
/// by the boot banner; exposed through [`total_usable_bytes`].
#[cfg(target_os = "none")]
static TOTAL_USABLE_BYTES: Once<u64> = Once::new();

#[cfg(target_os = "none")]
static USERSPACE_MODULE_ELF_SUMMARY: Once<Option<(x86_64::VirtAddr, usize)>> = Once::new();

#[cfg(target_os = "none")]
static USERSPACE_MODULE_ELF_BYTES: Once<Option<&'static [u8]>> = Once::new();

/// Cached bytes of the `userspace_hello.elf` Limine module, snapshotted during
/// `init()` before BOOTLOADER_RECLAIMABLE is freed (same reason as
/// `USERSPACE_MODULE_ELF_BYTES`).
#[cfg(target_os = "none")]
static USERSPACE_HELLO_ELF_BYTES: Once<Option<&'static [u8]>> = Once::new();

/// 4 KiB. The only page size we care about right now.
pub const FRAME_SIZE: u64 = 4096;

/// A USABLE physical region described in a hardware-agnostic way.
/// Used both by the frame allocator and its host-side unit tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub len: u64,
}

impl Region {
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }
}

/// Initialize memory subsystems in-kernel: snapshot Limine's memory map
/// into the global frame allocator, bring up the heap, then wrap the
/// active page tables in our own mapper.
#[cfg(target_os = "none")]
pub fn init() {
    // Snapshot the total byte count of memory the frame allocator will
    // eventually own. That's USABLE up front plus BOOTLOADER_RECLAIMABLE,
    // which `paging::reclaim_bootloader_memory()` later feeds into the
    // allocator — if we only counted USABLE, the banner would report
    // `free > total` after reclaim. Snapshotted now because Limine's
    // memmap response lives in BOOTLOADER_RECLAIMABLE and disappears
    // once we release it.
    if let Some(resp) = crate::boot::MEMMAP_REQUEST.get_response() {
        let total: u64 = resp
            .entries()
            .iter()
            .filter(|e| {
                e.entry_type == limine::memory_map::EntryType::USABLE
                    || e.entry_type == limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE
            })
            .map(|e| e.length)
            .sum();
        TOTAL_USABLE_BYTES.call_once(|| total);
    }

    frame::init();

    // Reprogram PAT before we build any PTE that sets the PAT bit.
    // Today that's just the framebuffer WC mapping in the new PML4.
    pat::init();

    // Paging comes up before the heap now — `heap::init` maps its
    // initial slab through `paging::map_range` instead of carving
    // HHDM-addressed frames directly.
    let hhdm = crate::boot::HHDM_REQUEST
        .get_response()
        .expect("Limine HHDM response missing");
    paging::init(x86_64::VirtAddr::new(hhdm.offset()));

    // Snapshot Limine module metadata before reclaiming BOOTLOADER_RECLAIMABLE
    // memory; the response structs themselves live there.
    // Snapshot both the parsed summary and the raw file slice before
    // BOOTLOADER_RECLAIMABLE is released. The bytes themselves live in
    // EXECUTABLE_AND_MODULES (preserved) so the &'static slice stays
    // valid after reclaim; only Limine's response structs go away.
    USERSPACE_MODULE_ELF_BYTES.call_once(elf::first_loaded_module_bytes);
    USERSPACE_MODULE_ELF_SUMMARY.call_once(elf::first_loaded_module_elf_summary);
    USERSPACE_HELLO_ELF_BYTES.call_once(elf::hello_module_bytes);

    heap::init();
    crate::arch::x86_64::ist_guard::install();

    // Build a clean kernel-owned PML4 from the now-populated mapper
    // state and swap CR3 to it. After this point, Limine's original
    // page-table tree is no longer reachable.
    paging::build_and_switch_kernel_pml4();

    // Reclaim the original Limine PML4's intermediate page-table frames
    // and all BOOTLOADER_RECLAIMABLE regions now that we no longer need
    // the bootloader's page-table tree or its data structures.
    paging::reclaim_bootloader_memory();
}

/// Total bytes of USABLE physical memory reported by Limine at boot.
/// Snapshotted during [`init`]; returns `0` when the memmap response
/// was missing (host builds, tests that don't call `mem::init`).
#[cfg(target_os = "none")]
pub fn total_usable_bytes() -> u64 {
    TOTAL_USABLE_BYTES.get().copied().unwrap_or(0)
}

/// Return the parsed entry point and loadable-segment count for the first
/// userspace module delivered by Limine, if present and well-formed.
#[cfg(target_os = "none")]
pub fn userspace_module_elf_summary() -> Option<(x86_64::VirtAddr, usize)> {
    USERSPACE_MODULE_ELF_SUMMARY.get().copied().flatten()
}

/// Raw bytes of the first Limine-delivered userspace module ELF file,
/// snapshotted during `init()` before BOOTLOADER_RECLAIMABLE is freed.
#[cfg(target_os = "none")]
pub fn userspace_module_elf_bytes() -> Option<&'static [u8]> {
    USERSPACE_MODULE_ELF_BYTES.get().copied().flatten()
}

/// Raw bytes of the `userspace_hello.elf` Limine module, snapshotted during
/// `init()` before `BOOTLOADER_RECLAIMABLE` is freed. Returns `None` if the
/// module was not included in the ISO.
#[cfg(target_os = "none")]
pub fn userspace_hello_elf_bytes() -> Option<&'static [u8]> {
    USERSPACE_HELLO_ELF_BYTES.get().copied().flatten()
}
