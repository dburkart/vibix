//! Bump physical-frame allocator.
//!
//! Walks an ordered slice of USABLE `Region`s, handing out 4 KiB frames
//! in ascending physical order. Frames are never returned — this is a
//! one-way allocator, appropriate for one-shot boot allocations (e.g.
//! the kernel heap). A reclaiming allocator is a later milestone.
//!
//! Kept free of `limine` and `x86_64` types so its bookkeeping can be
//! unit-tested on the host.

use super::{Region, FRAME_SIZE};

pub struct BumpFrameAllocator<'a> {
    regions: &'a [Region],
    /// Next candidate physical address. Always frame-aligned.
    cursor: u64,
    /// Index into `regions` we're currently carving from.
    region_idx: usize,
}

impl<'a> BumpFrameAllocator<'a> {
    /// Construct an allocator over the given USABLE regions. Regions
    /// should be non-overlapping; ordering is not required but starting
    /// at the lowest `start` gives deterministic output.
    pub fn new(regions: &'a [Region]) -> Self {
        let mut me = Self { regions, cursor: 0, region_idx: 0 };
        me.advance_to_next_region();
        me
    }

    fn advance_to_next_region(&mut self) {
        while self.region_idx < self.regions.len() {
            let r = &self.regions[self.region_idx];
            let aligned = align_up(r.start, FRAME_SIZE);
            if aligned + FRAME_SIZE <= r.start + r.len {
                self.cursor = aligned;
                return;
            }
            self.region_idx += 1;
        }
    }

    /// Allocate one 4 KiB physical frame. Returns the frame's starting
    /// physical address, or `None` when all regions are exhausted.
    pub fn allocate_frame(&mut self) -> Option<u64> {
        while self.region_idx < self.regions.len() {
            let region = self.regions[self.region_idx];
            let end = region.start + region.len;
            if self.cursor + FRAME_SIZE <= end {
                let frame = self.cursor;
                self.cursor += FRAME_SIZE;
                return Some(frame);
            }
            self.region_idx += 1;
            self.advance_to_next_region();
        }
        None
    }

    /// Allocate `count` *contiguous* frames within a single region.
    /// Used by heap init to carve a big-enough slab in one go.
    /// Returns the starting physical address.
    pub fn allocate_contiguous(&mut self, count: u64) -> Option<u64> {
        let needed = count * FRAME_SIZE;
        while self.region_idx < self.regions.len() {
            let region = self.regions[self.region_idx];
            let end = region.start + region.len;
            if self.cursor + needed <= end {
                let start = self.cursor;
                self.cursor += needed;
                return Some(start);
            }
            self.region_idx += 1;
            self.advance_to_next_region();
        }
        None
    }
}

fn align_up(x: u64, a: u64) -> u64 {
    (x + a - 1) & !(a - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }

    #[test]
    fn single_region_yields_frames_in_order() {
        let regions = [Region::new(0x1000, 0x4000)]; // 4 frames
        let mut a = BumpFrameAllocator::new(&regions);
        assert_eq!(a.allocate_frame(), Some(0x1000));
        assert_eq!(a.allocate_frame(), Some(0x2000));
        assert_eq!(a.allocate_frame(), Some(0x3000));
        assert_eq!(a.allocate_frame(), Some(0x4000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn unaligned_region_start_is_rounded_up() {
        let regions = [Region::new(0x1100, 0x3000)]; // not frame-aligned
        let mut a = BumpFrameAllocator::new(&regions);
        // Region spans [0x1100, 0x4100). Aligned start = 0x2000. Only
        // frames [0x2000, 0x3000) and [0x3000, 0x4000) fit fully; the
        // next would end at 0x5000, past the region.
        assert_eq!(a.allocate_frame(), Some(0x2000));
        assert_eq!(a.allocate_frame(), Some(0x3000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn walks_across_multiple_regions() {
        let regions = [
            Region::new(0x1000, 0x2000), // 2 frames
            Region::new(0x10000, 0x1000), // 1 frame
        ];
        let mut a = BumpFrameAllocator::new(&regions);
        assert_eq!(a.allocate_frame(), Some(0x1000));
        assert_eq!(a.allocate_frame(), Some(0x2000));
        assert_eq!(a.allocate_frame(), Some(0x10000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn region_too_small_is_skipped() {
        // 0x800 < one frame: region contributes nothing.
        let regions = [Region::new(0x1000, 0x800), Region::new(0x10000, 0x1000)];
        let mut a = BumpFrameAllocator::new(&regions);
        assert_eq!(a.allocate_frame(), Some(0x10000));
        assert_eq!(a.allocate_frame(), None);
    }

    #[test]
    fn allocate_contiguous_stays_within_a_region() {
        let regions = [
            Region::new(0x1000, 0x2000), // 2 frames — too small
            Region::new(0x10000, 0x10000), // 16 frames
        ];
        let mut a = BumpFrameAllocator::new(&regions);
        // 4 frames needed; region 0 can't fit → must come from region 1.
        assert_eq!(a.allocate_contiguous(4), Some(0x10000));
        // Subsequent single-frame allocs continue inside region 1.
        assert_eq!(a.allocate_frame(), Some(0x14000));
    }

    #[test]
    fn exhaustion_is_sticky() {
        let regions = [Region::new(0x1000, 0x1000)];
        let mut a = BumpFrameAllocator::new(&regions);
        assert!(a.allocate_frame().is_some());
        assert_eq!(a.allocate_frame(), None);
        assert_eq!(a.allocate_frame(), None);
    }
}
