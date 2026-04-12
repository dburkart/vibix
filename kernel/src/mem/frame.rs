//! Bitmap physical-frame allocator.
//!
//! One bit per 4 KiB frame. A set bit means "used", a clear bit "free".
//! Bits outside Limine's USABLE regions (and bits past the tracked
//! capacity) are kept set forever so the scanner skips them.
//!
//! Constant-time deallocate, roughly linear-in-bitmap-words allocate
//! (with a `next_hint` to skip past the already-scanned prefix on the
//! common case). Fine for the scales we care about — 4 GiB of RAM is
//! 128 KiB of bitmap, 16384 `u64` words.
//!
//! Kept free of `limine` and `x86_64` types so its bookkeeping can be
//! unit-tested on the host.

use super::{Region, FRAME_SIZE};

pub struct BitmapFrameAllocator<'a> {
    /// Bit `i` tracks frame at physical address `i * FRAME_SIZE`.
    bitmap: &'a mut [u64],
    /// Number of frames the caller told us to track. Bits in
    /// `[total_frames, bitmap.len() * 64)` are pinned set.
    total_frames: usize,
    /// Lowest frame index that might be free. Maintained as a hint, not
    /// a guarantee: allocate scans forward from here and wraps once.
    next_hint: usize,
}

impl<'a> BitmapFrameAllocator<'a> {
    /// Build an allocator covering `[0, total_frames)` frames. `bitmap`
    /// must have at least `ceil(total_frames / 64)` words.
    ///
    /// All tracked frames start marked used; pass USABLE regions to
    /// `release_region` (done for you by [`Self::with_regions`]) to mark
    /// them free. Frames in `[total_frames, bitmap.len() * 64)` stay
    /// pinned so the scanner never hands them out.
    pub fn new(bitmap: &'a mut [u64], total_frames: usize) -> Self {
        assert!(
            bitmap.len() * 64 >= total_frames,
            "bitmap too small for {total_frames} frames",
        );
        for word in bitmap.iter_mut() {
            *word = !0u64;
        }
        Self {
            bitmap,
            total_frames,
            next_hint: 0,
        }
    }

    /// Convenience constructor: mark every frame used, then release the
    /// frames covered by `regions`.
    pub fn with_regions(bitmap: &'a mut [u64], total_frames: usize, regions: &[Region]) -> Self {
        let mut me = Self::new(bitmap, total_frames);
        for r in regions {
            me.release_region(*r);
        }
        me
    }

    /// Mark all frames fully inside `region` as free.
    pub fn release_region(&mut self, region: Region) {
        let region_end = region.start.saturating_add(region.len);
        let start = align_up(region.start, FRAME_SIZE);
        if start >= region_end || region_end - start < FRAME_SIZE {
            return;
        }
        let mut addr = start;
        while addr + FRAME_SIZE <= region_end {
            let idx = (addr / FRAME_SIZE) as usize;
            if idx < self.total_frames {
                self.clear_bit(idx);
                if idx < self.next_hint {
                    self.next_hint = idx;
                }
            }
            addr += FRAME_SIZE;
        }
    }

    /// Allocate one 4 KiB physical frame. Returns the frame's starting
    /// physical address, or `None` if the pool is exhausted.
    pub fn allocate_frame(&mut self) -> Option<u64> {
        let total_words = self.bitmap.len();
        let start_word = self.next_hint / 64;
        for offset in 0..total_words {
            let w = (start_word + offset) % total_words;
            let word = self.bitmap[w];
            if word == !0u64 {
                continue;
            }
            let bit = (!word).trailing_zeros() as usize;
            let idx = w * 64 + bit;
            if idx >= self.total_frames {
                continue;
            }
            self.bitmap[w] |= 1u64 << bit;
            self.next_hint = idx + 1;
            return Some((idx as u64) * FRAME_SIZE);
        }
        None
    }

    /// Return a previously-allocated frame to the pool. Panics on
    /// double-free or on addresses outside the tracked range.
    pub fn deallocate_frame(&mut self, phys: u64) {
        assert!(
            phys & (FRAME_SIZE - 1) == 0,
            "deallocate_frame: {phys:#x} is not frame-aligned",
        );
        let idx = (phys / FRAME_SIZE) as usize;
        assert!(
            idx < self.total_frames,
            "deallocate_frame: {phys:#x} outside tracked range",
        );
        assert!(
            self.get_bit(idx),
            "deallocate_frame: double-free of {phys:#x}",
        );
        self.clear_bit(idx);
        if idx < self.next_hint {
            self.next_hint = idx;
        }
    }

    /// Number of currently-free tracked frames.
    pub fn free_frames(&self) -> usize {
        let total_bits = self.bitmap.len() * 64;
        let set_bits: usize = self.bitmap.iter().map(|w| w.count_ones() as usize).sum();
        let clear_bits = total_bits - set_bits;
        // `clear_bits` only counts bits in `[0, total_frames)` because
        // we pin the tail set in `new`. No subtraction needed.
        debug_assert!(clear_bits <= self.total_frames);
        clear_bits
    }

    fn clear_bit(&mut self, idx: usize) {
        self.bitmap[idx / 64] &= !(1u64 << (idx % 64));
    }

    fn get_bit(&self, idx: usize) -> bool {
        (self.bitmap[idx / 64] >> (idx % 64)) & 1 == 1
    }
}

fn align_up(x: u64, a: u64) -> u64 {
    (x + a - 1) & !(a - 1)
}

// --- Global allocator, populated at boot --------------------------------

/// Maximum distinct USABLE regions we snapshot from the Limine memmap.
/// QEMU's `q35` machine reports ~16 entries with a handful of USABLE —
/// 64 is comfortable headroom for real hardware.
pub const MAX_REGIONS: usize = 64;

/// Largest physical address we're willing to track in the bitmap. Sized
/// for 4 GiB of RAM; a higher USABLE region's top panics at init. 4 GiB
/// → 1 Mi frames → 16384 `u64` words → 128 KiB of `.bss`.
pub const MAX_PHYS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const BITMAP_WORDS: usize = (MAX_PHYS_BYTES / FRAME_SIZE / 64) as usize;

#[cfg(target_os = "none")]
mod global {
    use super::{BitmapFrameAllocator, Region, BITMAP_WORDS, MAX_PHYS_BYTES, MAX_REGIONS};
    use crate::boot::MEMMAP_REQUEST;
    use spin::{Mutex, Once};

    static REGIONS: Once<([Region; MAX_REGIONS], usize)> = Once::new();
    // Zero-initialized so the bitmap lives in `.bss` instead of `.data`
    // (saves ~128 KiB in the kernel image). `BitmapFrameAllocator::new`
    // writes `!0` to every word before handing out any frame, so the
    // initial value here is irrelevant for correctness.
    static mut BITMAP: [u64; BITMAP_WORDS] = [0u64; BITMAP_WORDS];
    static ALLOCATOR: Once<Mutex<BitmapFrameAllocator<'static>>> = Once::new();

    pub fn init() {
        let memmap = MEMMAP_REQUEST
            .get_response()
            .expect("Limine memory-map response missing");

        let regions = REGIONS.call_once(|| {
            let mut buf = [Region::new(0, 0); MAX_REGIONS];
            let mut n = 0;
            let mut max_end: u64 = 0;
            for entry in memmap.entries() {
                if entry.entry_type == limine::memory_map::EntryType::USABLE {
                    assert!(n < MAX_REGIONS, "more USABLE regions than MAX_REGIONS");
                    buf[n] = Region::new(entry.base, entry.length);
                    n += 1;
                    let end = entry.base.saturating_add(entry.length);
                    if end > max_end {
                        max_end = end;
                    }
                }
            }
            assert!(
                max_end <= MAX_PHYS_BYTES,
                "USABLE region ends at {:#x}, above MAX_PHYS_BYTES = {:#x}",
                max_end,
                MAX_PHYS_BYTES,
            );
            (buf, n)
        });
        let slice: &'static [Region] = &regions.0[..regions.1];

        // SAFETY: init runs exactly once; we hand the bitmap's unique
        // &'static mut to the Once-wrapped allocator and never touch the
        // static again.
        let bitmap: &'static mut [u64] = unsafe {
            let ptr = core::ptr::addr_of_mut!(BITMAP) as *mut u64;
            core::slice::from_raw_parts_mut(ptr, BITMAP_WORDS)
        };
        let total_frames = (MAX_PHYS_BYTES / super::FRAME_SIZE) as usize;
        ALLOCATOR.call_once(|| {
            Mutex::new(BitmapFrameAllocator::with_regions(
                bitmap,
                total_frames,
                slice,
            ))
        });
    }

    pub fn global() -> &'static Mutex<BitmapFrameAllocator<'static>> {
        ALLOCATOR.get().expect("frame::init not called")
    }
}

#[cfg(target_os = "none")]
pub use global::{global, init};

/// Number of free 4 KiB physical frames in the global allocator. Briefly
/// locks the allocator — suitable for diagnostics, not hot paths.
#[cfg(target_os = "none")]
pub fn free_frames() -> usize {
    global().lock().free_frames()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(words: usize, total_frames: usize) -> (Vec<u64>, usize) {
        (vec![!0u64; words], total_frames)
    }

    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }

    #[test]
    fn single_region_yields_frames_in_order() {
        let (mut bm, n) = mk(1, 8);
        let regions = [Region::new(0x1000, 0x4000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        assert_eq!(a.allocate_frame(), Some(0x1000));
        assert_eq!(a.allocate_frame(), Some(0x2000));
        assert_eq!(a.allocate_frame(), Some(0x3000));
        assert_eq!(a.allocate_frame(), Some(0x4000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn unaligned_region_start_is_rounded_up() {
        let (mut bm, n) = mk(1, 8);
        let regions = [Region::new(0x1100, 0x3000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        // Region spans [0x1100, 0x4100). Aligned start = 0x2000. Frames
        // [0x2000, 0x3000) and [0x3000, 0x4000) fit; [0x4000, 0x5000)
        // would run past the region end.
        assert_eq!(a.allocate_frame(), Some(0x2000));
        assert_eq!(a.allocate_frame(), Some(0x3000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn walks_across_multiple_regions() {
        let (mut bm, n) = mk(4, 64);
        let regions = [Region::new(0x1000, 0x2000), Region::new(0x10000, 0x1000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        assert_eq!(a.allocate_frame(), Some(0x1000));
        assert_eq!(a.allocate_frame(), Some(0x2000));
        assert_eq!(a.allocate_frame(), Some(0x10000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn region_too_small_is_skipped() {
        let (mut bm, n) = mk(4, 64);
        let regions = [Region::new(0x1000, 0x800), Region::new(0x10000, 0x1000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        assert_eq!(a.allocate_frame(), Some(0x10000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn exhaustion_is_sticky() {
        let (mut bm, n) = mk(1, 2);
        let regions = [Region::new(0x1000, 0x1000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        assert!(a.allocate_frame().is_some());
        assert_eq!(a.allocate_frame(), None);
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn dealloc_returns_frame_to_pool() {
        let (mut bm, n) = mk(1, 8);
        let regions = [Region::new(0x0, 0x4000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        let f0 = a.allocate_frame().unwrap();
        let f1 = a.allocate_frame().unwrap();
        let f2 = a.allocate_frame().unwrap();
        assert_eq!(a.free_frames(), 1);
        a.deallocate_frame(f1);
        assert_eq!(a.free_frames(), 2);
        // Hint moved back to f1 — next alloc should pick it up.
        assert_eq!(a.allocate_frame(), Some(f1));
        a.deallocate_frame(f0);
        a.deallocate_frame(f2);
    }

    #[test]
    fn map_unmap_loop_returns_free_frames_to_baseline() {
        let (mut bm, n) = mk(2, 64);
        let regions = [Region::new(0x0, 64 * 4096)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        let baseline = a.free_frames();
        for _ in 0..1000 {
            let f = a.allocate_frame().unwrap();
            a.deallocate_frame(f);
        }
        assert_eq!(a.free_frames(), baseline);
    }

    #[test]
    fn free_frames_counts_only_tracked_bits() {
        // Bitmap has 128 bits of storage but we only track 10.
        let (mut bm, n) = mk(2, 10);
        let regions = [Region::new(0x0, 10 * 4096)];
        let a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        assert_eq!(a.free_frames(), 10);
    }

    #[test]
    #[should_panic(expected = "double-free")]
    fn double_free_panics() {
        let (mut bm, n) = mk(1, 4);
        let regions = [Region::new(0x0, 0x4000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        let f = a.allocate_frame().unwrap();
        a.deallocate_frame(f);
        a.deallocate_frame(f);
    }

    #[test]
    #[should_panic(expected = "outside tracked range")]
    fn dealloc_out_of_range_panics() {
        let (mut bm, n) = mk(1, 4);
        let regions = [Region::new(0x0, 0x4000)];
        let mut a = BitmapFrameAllocator::with_regions(&mut bm, n, &regions);
        a.deallocate_frame(0x10000);
    }
}
