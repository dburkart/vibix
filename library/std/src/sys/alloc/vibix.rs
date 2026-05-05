//! System allocator for vibix -- delegates to `vibix_abi::alloc::VibixAllocator`.

use crate::alloc::{GlobalAlloc, Layout, System};

#[stable(feature = "alloc_system_type", since = "1.28.0")]
unsafe impl GlobalAlloc for System {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: caller guarantees layout is valid.
        unsafe { vibix_abi::alloc::VibixAllocator.alloc(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: caller guarantees ptr was allocated with this allocator.
        unsafe { vibix_abi::alloc::VibixAllocator.dealloc(ptr, layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: caller guarantees ptr was allocated with this allocator.
        unsafe { vibix_abi::alloc::VibixAllocator.realloc(ptr, layout, new_size) }
    }
}
