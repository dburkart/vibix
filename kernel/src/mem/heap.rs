//! Kernel heap with grow-on-demand. Reserves a 16 MiB virtual range
//! inside the higher half, backs the first 1 MiB with frames at init,
//! and maps more 64 KiB chunks on allocator OOM until the cap.
//!
//! The allocator wraps `linked_list_allocator::LockedHeap` with a
//! `GlobalAlloc` impl that, on null, takes a grow lock, maps the next
//! chunk via [`paging::map_range`], calls `Heap::extend`, and retries.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use linked_list_allocator::LockedHeap;
use spin::Mutex;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

use super::{paging, FRAME_SIZE};
use crate::serial_println;

/// Base of the reserved heap VA window. Lives in the higher half above
/// Limine's HHDM (Limine puts HHDM at 0xFFFF_8000_… typically); the
/// paging integration test also uses `0xFFFF_C000_…` addresses outside
/// our cap, so no collision.
pub const HEAP_BASE: usize = 0xFFFF_C000_0000_0000;
/// Boot-time backed portion of the heap. Kept at 1 MiB so the smoke
/// marker `"heap: 1024 KiB"` stays unchanged.
pub const INITIAL_HEAP_SIZE: usize = 1024 * 1024;
/// Hard cap. Growth stops here and the allocator returns null.
pub const HEAP_MAX_SIZE: usize = 16 * 1024 * 1024;
/// Frames mapped per grow step — 64 KiB picked so we amortize the
/// map + extend cost without wasting much when demand is light.
pub const GROW_CHUNK_FRAMES: u64 = 16;
const GROW_CHUNK_BYTES: usize = (GROW_CHUNK_FRAMES * FRAME_SIZE) as usize;

pub struct GrowingHeap {
    inner: LockedHeap,
    mapped: AtomicUsize,
    grow_lock: Mutex<()>,
}

impl GrowingHeap {
    const fn new() -> Self {
        Self {
            inner: LockedHeap::empty(),
            mapped: AtomicUsize::new(0),
            grow_lock: Mutex::new(()),
        }
    }

    /// Bytes of VA currently backed by frames and handed to the
    /// underlying heap. Starts at `INITIAL_HEAP_SIZE`; monotonically
    /// increases up to `HEAP_MAX_SIZE`.
    pub fn mapped_size(&self) -> usize {
        self.mapped.load(Ordering::Acquire)
    }

    /// Map the next `GROW_CHUNK_BYTES` (or less if we're bumping the
    /// cap) past the current top and call `Heap::extend`. Returns false
    /// if we're already at the cap or the map failed.
    fn grow(&self) -> bool {
        let _g = self.grow_lock.lock();
        let mapped = self.mapped.load(Ordering::Acquire);
        if mapped >= HEAP_MAX_SIZE {
            return false;
        }
        let remaining = HEAP_MAX_SIZE - mapped;
        let chunk = GROW_CHUNK_BYTES.min(remaining);
        let start = VirtAddr::new((HEAP_BASE + mapped) as u64);
        let frames = (chunk as u64) / FRAME_SIZE;
        if paging::map_range(
            start,
            frames,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        )
        .is_err()
        {
            return false;
        }
        // SAFETY: just mapped `chunk` bytes contiguous with the current
        // heap top; they're owned by the heap from here on.
        unsafe { self.inner.lock().extend(chunk) };
        self.mapped.fetch_add(chunk, Ordering::Release);
        true
    }
}

unsafe impl GlobalAlloc for GrowingHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        loop {
            let p = self.inner.alloc(layout);
            if !p.is_null() {
                return p;
            }
            if !self.grow() {
                return ptr::null_mut();
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: GrowingHeap = GrowingHeap::new();

/// Bytes of VA currently backed by the heap. Exposed for tests and
/// diagnostics.
pub fn mapped_size() -> usize {
    ALLOCATOR.mapped_size()
}

/// Map the initial slab and hand it to the inner heap. Requires
/// `paging::init` to have run so `map_range` is live.
pub fn init() {
    let frames = (INITIAL_HEAP_SIZE as u64) / FRAME_SIZE;
    paging::map_range(
        VirtAddr::new(HEAP_BASE as u64),
        frames,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    )
    .expect("failed to map initial heap range");

    unsafe {
        ALLOCATOR
            .inner
            .lock()
            .init(HEAP_BASE as *mut u8, INITIAL_HEAP_SIZE);
    }
    ALLOCATOR.mapped.store(INITIAL_HEAP_SIZE, Ordering::Release);

    serial_println!(
        "heap: {} KiB @ {:#x} (reserved {} KiB, grows in {} KiB chunks)",
        INITIAL_HEAP_SIZE / 1024,
        HEAP_BASE,
        HEAP_MAX_SIZE / 1024,
        GROW_CHUNK_BYTES / 1024,
    );
}
