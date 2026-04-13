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

pub mod frame;
pub mod refcount;

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
pub mod vma;

#[cfg(any(target_os = "none", test))]
pub mod addrspace;

#[cfg(target_os = "none")]
use spin::Once;

#[cfg(target_os = "none")]
static USERSPACE_MODULE_ELF_SUMMARY: Once<Option<(x86_64::VirtAddr, usize)>> = Once::new();

#[cfg(target_os = "none")]
static USERSPACE_MODULE_ELF_BYTES: Once<Option<&'static [u8]>> = Once::new();

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
