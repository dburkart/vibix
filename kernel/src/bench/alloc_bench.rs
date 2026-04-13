//! `kmalloc` / `kfree` round-trip timing for a spread of sizes.
//!
//! Each sample times a paired `alloc` + `dealloc` of one allocation.
//! That bundles both halves into one measurement; the returned
//! numbers reflect the whole round-trip cost rather than alloc alone.

use alloc::alloc::{alloc, dealloc, Layout};

use super::{measure, Stats};

/// A spread of sizes small callers actually hit in practice: a few
/// bytes (node-like), a cache-line, a page-and-change, and a
/// multi-page allocation for larger working sets.
const SIZES: &[usize] = &[16, 64, 256, 1024, 4096];

const ITERS: u32 = 1024;

pub fn run() -> alloc::vec::Vec<(usize, Stats)> {
    use crate::serial_println;
    let mut out = alloc::vec::Vec::with_capacity(SIZES.len());
    for &size in SIZES {
        serial_println!("bench: alloc size={}", size);
        // Layout::from_size_align: align=8 matches the natural word
        // alignment the linked_list_allocator hands back for small
        // sizes anyway, and keeps the benchmark uniform across sizes.
        let layout = Layout::from_size_align(size, 8).expect("bench: valid layout");
        // Warm the arena: the first handful of allocs at each size
        // hit either fresh space or the grow lock, producing outliers
        // that skew min downward and median upward simultaneously.
        for _ in 0..32 {
            unsafe {
                let p = alloc(layout);
                if !p.is_null() {
                    dealloc(p, layout);
                }
            }
        }
        let stats = measure(ITERS, || unsafe {
            let p = alloc(layout);
            // Writing the first byte forces the allocator's address
            // range to actually be mapped — grow lock + page walk get
            // amortised into the sample for sizes that cross the
            // current heap tail.
            if !p.is_null() {
                core::ptr::write_volatile(p, 0);
                dealloc(p, layout);
            }
        });
        out.push((size, stats));
    }
    out
}
