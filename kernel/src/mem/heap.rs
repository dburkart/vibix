//! Kernel heap: carve a contiguous 1 MiB slab from physical memory via
//! the global bump frame allocator, then hand it to `linked_list_allocator`.
//!
//! The slab is addressed through Limine's HHDM (Higher-Half Direct Map),
//! which already covers all physical memory in the virtual address space
//! Limine sets up.

use linked_list_allocator::LockedHeap;

use super::frame;
use super::FRAME_SIZE;
use crate::boot::HHDM_REQUEST;
use crate::serial_println;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// 256 × 4 KiB = 1 MiB. Room for early `Vec`/`Box` usage; grows later.
pub const HEAP_FRAMES: u64 = 256;
pub const HEAP_SIZE: usize = (HEAP_FRAMES * FRAME_SIZE) as usize;

pub fn init() {
    let hhdm = HHDM_REQUEST
        .get_response()
        .expect("Limine HHDM response missing");

    let heap_phys = frame::global()
        .lock()
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
