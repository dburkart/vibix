//! Physical-frame allocator + kernel heap.
//!
//! Milestone 2 keeps things deliberately minimal:
//!  - `frame::BumpFrameAllocator` bumps through Limine's USABLE regions.
//!    Pure logic, no `limine`/`x86_64` dependencies → host-testable.
//!  - `heap` pulls one contiguous 1 MiB slice of frames and hands it to
//!    `linked_list_allocator::LockedHeap`, which becomes the kernel's
//!    global allocator. Heap memory is addressed through Limine's HHDM.

pub mod frame;

#[cfg(target_os = "none")]
pub mod heap;

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

/// Initialize memory subsystems in-kernel: build the frame allocator
/// from Limine's memory map, then bring up the heap.
#[cfg(target_os = "none")]
pub fn init() {
    heap::init();
}
