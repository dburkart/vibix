//! Global allocator for vibix userspace.
//!
//! Uses `brk` for small allocations (< 128 KiB) and `mmap` for large ones.
//! This is the allocator that std's `System` allocator delegates to on vibix.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::syscall;

/// Syscall numbers (Linux x86_64 convention).
const SYS_BRK: u64 = 12;
const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;

/// Allocations at or above this size use mmap instead of brk.
const MMAP_THRESHOLD: usize = 128 * 1024;

/// mmap protection and flag constants.
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

/// A simple bump allocator backed by `brk` for small allocations.
///
/// Large allocations (>= MMAP_THRESHOLD) go directly to `mmap` so they can be
/// individually `munmap`'d without fragmenting the brk region.
pub struct VibixAllocator;

/// Current brk pointer.  Initialized lazily on first allocation.
static BRK_CURRENT: AtomicUsize = AtomicUsize::new(0);

/// Initialize the brk region by querying the current program break.
fn brk_init() -> usize {
    let current = unsafe { syscall::syscall1(SYS_BRK, 0) } as usize;
    BRK_CURRENT.store(current, Ordering::Relaxed);
    current
}

unsafe impl GlobalAlloc for VibixAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        if size >= MMAP_THRESHOLD {
            return mmap_alloc(size);
        }

        // Bump-allocate from the brk region.
        loop {
            let mut current = BRK_CURRENT.load(Ordering::Relaxed);
            if current == 0 {
                current = brk_init();
            }

            // Align up.
            let aligned = (current + align - 1) & !(align - 1);
            let new_brk = aligned + size;

            // Extend the program break.
            let result = unsafe { syscall::syscall1(SYS_BRK, new_brk as u64) } as usize;
            if result < new_brk {
                // brk failed -- cannot grow the heap.  Return null (OOM).
                // We intentionally do NOT fall back to mmap here because
                // dealloc() uses the size threshold to decide whether to
                // munmap(); a small mmap'd block would never be freed.
                return ptr::null_mut();
            }

            // Try to commit our bump.  If another thread raced us, retry.
            match BRK_CURRENT.compare_exchange(
                current,
                new_brk,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(_) => continue,
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size();
        if size >= MMAP_THRESHOLD {
            unsafe {
                syscall::syscall2(SYS_MUNMAP, ptr as u64, size as u64);
            }
        }
        // Small allocations from brk are not individually freed (bump allocator).
    }
}

/// Allocate via anonymous mmap.
fn mmap_alloc(size: usize) -> *mut u8 {
    let ret = unsafe {
        syscall::syscall6(
            SYS_MMAP,
            0,                           // addr (kernel chooses)
            size as u64,                 // length
            PROT_READ | PROT_WRITE,      // prot
            MAP_PRIVATE | MAP_ANONYMOUS, // flags
            u64::MAX,                    // fd (-1)
            0,                           // offset
        )
    };
    // mmap returns MAP_FAILED (typically -1..-4095) on error.
    if ret < 0 && ret > -4096 {
        return ptr::null_mut();
    }
    ret as *mut u8
}
