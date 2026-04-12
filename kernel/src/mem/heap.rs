//! Kernel heap: carve a contiguous 1 MiB slab from physical memory via
//! our bump frame allocator, then hand it to `linked_list_allocator`.
//!
//! The slab is addressed through Limine's HHDM (Higher-Half Direct Map),
//! which already covers all physical memory in the virtual address space
//! Limine sets up. No paging work needed at this stage — that's the job
//! of milestone 3 when we take over the page tables ourselves.

use linked_list_allocator::LockedHeap;

use super::frame::BumpFrameAllocator;
use super::{Region, FRAME_SIZE};
use crate::boot::{HHDM_REQUEST, MEMMAP_REQUEST};
use crate::serial_println;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// 256 × 4 KiB = 1 MiB. Room for early `Vec`/`Box` usage; grows later.
pub const HEAP_FRAMES: u64 = 256;
pub const HEAP_SIZE: usize = (HEAP_FRAMES * FRAME_SIZE) as usize;

/// Maximum distinct USABLE regions we snapshot from the Limine memmap.
/// QEMU's `q35` machine reports ~16 entries with a handful of USABLE —
/// 64 is comfortable headroom for real hardware without heap help.
const MAX_REGIONS: usize = 64;

pub fn init() {
    let memmap = MEMMAP_REQUEST
        .get_response()
        .expect("Limine memory-map response missing");
    let hhdm = HHDM_REQUEST
        .get_response()
        .expect("Limine HHDM response missing");

    let mut regions_buf = [Region::new(0, 0); MAX_REGIONS];
    let mut n = 0;
    for entry in memmap.entries() {
        if entry.entry_type == limine::memory_map::EntryType::USABLE {
            assert!(n < MAX_REGIONS, "more USABLE regions than MAX_REGIONS");
            regions_buf[n] = Region::new(entry.base, entry.length);
            n += 1;
        }
    }
    let regions = &regions_buf[..n];

    let mut allocator = BumpFrameAllocator::new(regions);
    let heap_phys = allocator
        .allocate_contiguous(HEAP_FRAMES)
        .expect("no contiguous USABLE region large enough for the kernel heap");
    let heap_virt = heap_phys + hhdm.offset();

    unsafe {
        ALLOCATOR.lock().init(heap_virt as *mut u8, HEAP_SIZE);
    }

    serial_println!(
        "heap: {} KiB @ {:#x} (phys {:#x})",
        HEAP_SIZE / 1024,
        heap_virt,
        heap_phys
    );
}
