//! `VmaTree`: ordered, non-overlapping collection of [`Vma`]s keyed by
//! their start address, with split + merge on insert, unmap, and
//! `mprotect`. The data-structure layer of RFC 0001 — `mmap` /
//! `munmap` / `mprotect` over partial sub-ranges all end up calling
//! into one of the three methods below.
//!
//! Purely structural. No page-table reads or writes, no frame-allocator
//! traffic: `unmap_range` drops the `Arc<dyn VmObject>` each removed
//! VMA held (which may cascade into the VmObject's `Drop` and reclaim
//! backing frames), but it does **not** decrement per-frame refcounts
//! or tear down PTEs. The caller owns that — typically the fault
//! resolver or the `munmap` syscall implementation — because this layer
//! has no access to the page table.
//!
//! Lives alongside the older flat `VmaList` in `vma.rs` today; issue
//! #159 migrates task/PF handler call sites across and deletes the
//! list.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::mem::vmobject::VmObject;
use crate::mem::FRAME_SIZE;

/// User-visible `PROT_*` bits, mirrored out of `mman.h`. Stored as a
/// bare `u32` so the userspace ABI is independent of the kernel's
/// internal `PageTableFlags` choice.
pub type ProtUser = u32;

/// Raw bits of `x86_64::structures::paging::PageTableFlags`. Cached
/// alongside `prot_user` so the fault resolver can blit them into a
/// PTE without re-deriving them on every page fault.
pub type ProtPte = u64;

/// Sharing discipline. `Private` means CoW on fork; `Shared` means the
/// child sees the parent's writes (anon-shared / MAP_SHARED).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Share {
    Private,
    Shared,
}

/// One virtual-memory area: half-open `[start, end)` byte range backed
/// by `object` at `object_offset`, with user-visible protection
/// `prot_user` and cached PTE flags `prot_pte`.
///
/// `#[repr(C)]` so the layout is stable enough for eventual inspection
/// by a debugger / introspection tool; `_lock_seq` is the reserved
/// future-work slot for per-VMA seqlock ordering.
#[repr(C)]
pub struct Vma {
    pub start: usize,
    pub end: usize,
    pub prot_user: ProtUser,
    pub prot_pte: ProtPte,
    pub share: Share,
    pub object: Arc<dyn VmObject>,
    pub object_offset: usize,
    pub _lock_seq: u32,
}

impl Vma {
    /// Construct a VMA. Panics on unaligned or empty ranges — those are
    /// bugs at the caller, not runtime-recoverable conditions.
    pub fn new(
        start: usize,
        end: usize,
        prot_user: ProtUser,
        prot_pte: ProtPte,
        share: Share,
        object: Arc<dyn VmObject>,
        object_offset: usize,
    ) -> Self {
        assert!(
            start % (FRAME_SIZE as usize) == 0,
            "vma start {start:#x} must be page-aligned",
        );
        assert!(
            end % (FRAME_SIZE as usize) == 0,
            "vma end {end:#x} must be page-aligned",
        );
        assert!(start < end, "vma range [{start:#x},{end:#x}) is empty");
        assert!(
            object_offset % (FRAME_SIZE as usize) == 0,
            "vma object_offset {object_offset:#x} must be page-aligned",
        );
        Self {
            start,
            end,
            prot_user,
            prot_pte,
            share,
            object,
            object_offset,
            _lock_seq: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Two neighbouring VMAs can coalesce when `self.end == other.start`,
    /// they share the same protection / sharing discipline, point at the
    /// same `Arc<dyn VmObject>` (pointer-equal, not value-equal), and the
    /// right neighbour's `object_offset` is the natural continuation of
    /// the left's.
    fn mergeable_forward(&self, other: &Vma) -> bool {
        self.end == other.start
            && self.prot_user == other.prot_user
            && self.prot_pte == other.prot_pte
            && self.share == other.share
            && Arc::ptr_eq(&self.object, &other.object)
            && self.object_offset + self.len() == other.object_offset
    }

    /// Split this VMA at `addr` and return `(left, right)`. Both halves
    /// share the same `Arc<dyn VmObject>`; the right half's
    /// `object_offset` is bumped by the split delta. Panics if `addr`
    /// is not a strict interior boundary.
    fn split_at(self, addr: usize) -> (Vma, Vma) {
        assert!(
            self.start < addr && addr < self.end,
            "split_at: {addr:#x} is not interior to [{:#x},{:#x})",
            self.start,
            self.end,
        );
        assert!(
            addr % (FRAME_SIZE as usize) == 0,
            "split_at: {addr:#x} is not page-aligned",
        );
        let delta = addr - self.start;
        let left = Vma {
            start: self.start,
            end: addr,
            prot_user: self.prot_user,
            prot_pte: self.prot_pte,
            share: self.share,
            object: Arc::clone(&self.object),
            object_offset: self.object_offset,
            _lock_seq: 0,
        };
        let right = Vma {
            start: addr,
            end: self.end,
            prot_user: self.prot_user,
            prot_pte: self.prot_pte,
            share: self.share,
            object: self.object,
            object_offset: self.object_offset + delta,
            _lock_seq: 0,
        };
        (left, right)
    }
}

/// Ordered, non-overlapping set of [`Vma`]s keyed by `start` — the
/// maple-tree-equivalent replacement for the old flat `VmaList`. Public
/// API is iterator-only so a future swap to a different backing
/// structure (e.g. an actual maple tree) is internal.
pub struct VmaTree {
    map: BTreeMap<usize, Vma>,
}

impl Default for VmaTree {
    fn default() -> Self {
        Self::new()
    }
}

impl VmaTree {
    pub const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Find the VMA containing `addr`, if any. O(log n).
    pub fn find(&self, addr: usize) -> Option<&Vma> {
        self.map
            .range(..=addr)
            .next_back()
            .map(|(_, v)| v)
            .filter(|v| addr < v.end)
    }

    /// Iterate in ascending `start` order.
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.map.values()
    }

    /// Insert `vma`, merging with neighbours where possible. Panics if
    /// `vma` overlaps an existing entry — overlapping VMAs are a
    /// programmer bug, not a runtime condition.
    pub fn insert(&mut self, mut vma: Vma) {
        self.assert_no_overlap(vma.start, vma.end);

        // Merge backwards with left neighbours while each is mergeable.
        // Looping (rather than a single step) matters for callers like
        // `change_protection` that re-insert many keys in sequence: an
        // earlier re-insertion can leave behind a mergeable left chain
        // that the current insert must fully absorb.
        while let Some((&lstart, _)) = self.map.range(..vma.start).next_back() {
            let left = self.map.get(&lstart).unwrap();
            if !left.mergeable_forward(&vma) {
                break;
            }
            let mut left = self.map.remove(&lstart).unwrap();
            left.end = vma.end;
            // Keep `left`'s object / offset / prot — `vma`'s are equal
            // by the mergeability predicate.
            vma = left;
        }

        // Merge forwards with right neighbours while each is mergeable.
        // See the backward loop above for why this is a loop, not a
        // single step.
        while let Some((&rstart, _)) = self.map.range(vma.end..).next() {
            let right = self.map.get(&rstart).unwrap();
            if !vma.mergeable_forward(right) {
                break;
            }
            let right = self.map.remove(&rstart).unwrap();
            vma.end = right.end;
            // `right` is dropped here; its `Arc<dyn VmObject>` ref is
            // released. `vma.object` still carries an Arc of its own
            // (pointer-equal by mergeability).
            drop(right);
        }

        let prev = self.map.insert(vma.start, vma);
        debug_assert!(prev.is_none(), "VmaTree::insert: overlap slipped past");
    }

    /// Unmap `[start, end)`: split VMAs that straddle the boundaries,
    /// drop fully-contained VMAs. Structural only — PTE teardown and
    /// page-refcount decrements are the caller's job.
    pub fn unmap_range(&mut self, start: usize, end: usize) {
        assert!(
            start % (FRAME_SIZE as usize) == 0 && end % (FRAME_SIZE as usize) == 0,
            "unmap_range: [{start:#x},{end:#x}) must be page-aligned",
        );
        assert!(start < end, "unmap_range: empty range");

        // Collect starts of entries that overlap the range. Copy out of
        // the BTreeMap iterator so we can freely mutate below.
        let mut hits: alloc::vec::Vec<usize> = self
            .map
            .range(..end)
            .rev()
            .take_while(|(_, v)| v.end > start)
            .map(|(&k, _)| k)
            .collect();
        // Iterate lowest→highest so split positions remain predictable.
        hits.reverse();

        for vstart in hits {
            let v = self
                .map
                .remove(&vstart)
                .expect("hits are keys we just read");
            // Three shapes:
            //  fully contained  [v.start, v.end) ⊆ [start, end)     → drop
            //  straddles left   v.start < start && v.end > start    → keep left
            //  straddles right  v.start < end   && v.end > end      → keep right
            //  super-set        v.start < start && v.end > end      → keep both
            if v.start >= start && v.end <= end {
                drop(v);
                continue;
            }
            if v.start < start && v.end > end {
                // Super-set: split into left [v.start, start) and right [end, v.end).
                let (left, rest) = v.split_at(start);
                let (_mid, right) = rest.split_at(end);
                // _mid is the fully-contained chunk; its Arc drop is
                // deliberate here.
                drop(_mid);
                let prev_l = self.map.insert(left.start, left);
                debug_assert!(prev_l.is_none());
                let prev_r = self.map.insert(right.start, right);
                debug_assert!(prev_r.is_none());
                continue;
            }
            if v.start < start {
                // Straddles the left boundary — keep left, drop right.
                let (left, right) = v.split_at(start);
                drop(right);
                let prev = self.map.insert(left.start, left);
                debug_assert!(prev.is_none());
                continue;
            }
            if v.end > end {
                // Straddles the right boundary — keep right, drop left.
                let (left, right) = v.split_at(end);
                drop(left);
                let prev = self.map.insert(right.start, right);
                debug_assert!(prev.is_none());
                continue;
            }
            unreachable!(
                "unmap_range: VMA {:#x}..{:#x} matched no shape",
                v.start, v.end
            );
        }
    }

    /// Apply `(new_prot_user, new_prot_pte)` to every byte in
    /// `[start, end)`, splitting VMAs at the boundaries as needed and
    /// re-merging with neighbours that now share the same protection.
    pub fn change_protection(
        &mut self,
        start: usize,
        end: usize,
        new_prot_user: ProtUser,
        new_prot_pte: ProtPte,
    ) {
        assert!(
            start % (FRAME_SIZE as usize) == 0 && end % (FRAME_SIZE as usize) == 0,
            "change_protection: [{start:#x},{end:#x}) must be page-aligned",
        );
        assert!(start < end, "change_protection: empty range");

        // Pass 1: split at the boundaries so every touched VMA lies
        // entirely within the range.
        self.split_at_boundary(start);
        self.split_at_boundary(end);

        // Pass 2: rewrite prot on every VMA whose whole extent is
        // inside [start, end).
        let affected: alloc::vec::Vec<usize> =
            self.map.range(start..end).map(|(&k, _)| k).collect();
        for k in &affected {
            let v = self.map.get_mut(k).expect("affected keys exist");
            v.prot_user = new_prot_user;
            v.prot_pte = new_prot_pte;
        }

        // Pass 3: coalesce. Re-insert in order — `insert` handles the
        // forward+backward merge. A prior iteration's `insert` may have
        // already consumed the next affected key via forward-merge, so
        // skip keys that are no longer present instead of panicking.
        for k in affected {
            if let Some(v) = self.map.remove(&k) {
                self.insert(v);
            }
        }
    }

    /// Ensure no VMA straddles `boundary` — if one does, split it in
    /// place. No-op if `boundary` already falls on an existing edge.
    fn split_at_boundary(&mut self, boundary: usize) {
        let key = match self.map.range(..boundary).next_back().map(|(&k, _)| k) {
            Some(k) => k,
            None => return,
        };
        let v = self.map.get(&key).unwrap();
        if v.end <= boundary {
            return;
        }
        // Strictly interior — split.
        let v = self.map.remove(&key).unwrap();
        let (left, right) = v.split_at(boundary);
        self.map.insert(left.start, left);
        self.map.insert(right.start, right);
    }

    /// Remove the VMA whose `start` matches exactly. Returns the VMA
    /// if found. Unlike [`unmap_range`], this is an exact-match remove
    /// that does not split bordering VMAs.
    pub fn remove_exact(&mut self, start: usize) -> Option<Vma> {
        self.map.remove(&start)
    }

    fn assert_no_overlap(&self, start: usize, end: usize) {
        if let Some((_, left)) = self.map.range(..start).next_back() {
            assert!(
                left.end <= start,
                "VmaTree::insert: [{start:#x},{end:#x}) overlaps existing [{:#x},{:#x})",
                left.start,
                left.end,
            );
        }
        if let Some((_, right)) = self.map.range(start..).next() {
            assert!(
                right.start >= end,
                "VmaTree::insert: [{start:#x},{end:#x}) overlaps existing [{:#x},{:#x})",
                right.start,
                right.end,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::vmobject::{Access, AnonObject, VmFault, VmObject};

    // A lightweight `VmObject` host tests can hand to `Vma::new`
    // without having to route through the frame allocator or the
    // anon-object cache. Distinct `Arc`s of this type are pointer-
    // unequal, which is what the "merge rejected on different Arc"
    // test wants to exercise.
    struct StubObject {
        len: Option<usize>,
    }

    impl VmObject for StubObject {
        fn fault(&self, _offset: usize, _access: Access) -> Result<u64, VmFault> {
            Err(VmFault::OutOfMemory)
        }

        fn len_pages(&self) -> Option<usize> {
            self.len
        }

        fn clone_private(&self) -> Arc<dyn VmObject> {
            Arc::new(StubObject { len: self.len })
        }
    }

    fn stub() -> Arc<dyn VmObject> {
        Arc::new(StubObject { len: None })
    }

    fn vma(
        start: usize,
        end: usize,
        prot_user: ProtUser,
        obj: Arc<dyn VmObject>,
        object_offset: usize,
    ) -> Vma {
        Vma::new(start, end, prot_user, 0, Share::Private, obj, object_offset)
    }

    const R: ProtUser = 0x1;
    const RW: ProtUser = 0x3;
    const K: usize = 4096;

    #[test]
    fn insert_merges_adjacent_same_arc_and_offsets() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, K, RW, Arc::clone(&obj), 0));
        t.insert(vma(K, 2 * K, RW, obj, K));
        assert_eq!(t.len(), 1);
        let only = t.iter().next().unwrap();
        assert_eq!((only.start, only.end), (0, 2 * K));
        assert_eq!(only.object_offset, 0);
    }

    #[test]
    fn insert_merges_both_sides() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, K, RW, Arc::clone(&obj), 0));
        t.insert(vma(2 * K, 3 * K, RW, Arc::clone(&obj), 2 * K));
        // Middle chunk glues them.
        t.insert(vma(K, 2 * K, RW, obj, K));
        assert_eq!(t.len(), 1);
        let only = t.iter().next().unwrap();
        assert_eq!((only.start, only.end), (0, 3 * K));
    }

    #[test]
    fn insert_does_not_merge_across_distinct_arcs() {
        let a = stub();
        let b = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, K, RW, a, 0));
        t.insert(vma(K, 2 * K, RW, b, 0));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn insert_does_not_merge_across_different_prot() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, K, RW, Arc::clone(&obj), 0));
        t.insert(vma(K, 2 * K, R, obj, K));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn insert_does_not_merge_across_non_contiguous_offset() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, K, RW, Arc::clone(&obj), 0));
        // Offset jumps instead of continuing.
        t.insert(vma(K, 2 * K, RW, obj, 10 * K));
        assert_eq!(t.len(), 2);
    }

    #[test]
    #[should_panic(expected = "overlaps existing")]
    fn insert_overlap_panics() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, 2 * K, RW, Arc::clone(&obj), 0));
        t.insert(vma(K, 3 * K, RW, obj, 0));
    }

    #[test]
    fn find_hits_and_misses() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, K, RW, obj, 0));
        assert!(t.find(0).is_some());
        assert!(t.find(K - 1).is_some());
        assert!(t.find(K).is_none()); // half-open
        assert!(t.find(100 * K).is_none());
    }

    #[test]
    fn unmap_range_splits_both_sides() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, 4 * K, RW, obj, 0));
        t.unmap_range(K, 3 * K);
        let vs: alloc::vec::Vec<_> = t
            .iter()
            .map(|v| (v.start, v.end, v.object_offset))
            .collect();
        assert_eq!(vs, [(0, K, 0), (3 * K, 4 * K, 3 * K)]);
    }

    #[test]
    fn unmap_range_drops_fully_contained() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(K, 2 * K, RW, Arc::clone(&obj), 0));
        t.insert(vma(3 * K, 4 * K, RW, obj, 0));
        t.unmap_range(0, 5 * K);
        assert!(t.is_empty());
    }

    #[test]
    fn unmap_range_straddle_left_only() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, 2 * K, RW, obj, 0));
        t.unmap_range(K, 10 * K);
        let vs: alloc::vec::Vec<_> = t.iter().map(|v| (v.start, v.end)).collect();
        assert_eq!(vs, [(0, K)]);
    }

    #[test]
    fn unmap_range_straddle_right_only() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(2 * K, 4 * K, RW, obj, 0));
        t.unmap_range(0, 3 * K);
        let vs: alloc::vec::Vec<_> = t
            .iter()
            .map(|v| (v.start, v.end, v.object_offset))
            .collect();
        assert_eq!(vs, [(3 * K, 4 * K, K)]);
    }

    #[test]
    fn change_protection_remerges_after_downgrade_restore() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, 3 * K, RW, obj, 0));
        assert_eq!(t.len(), 1);
        // Downgrade middle page.
        t.change_protection(K, 2 * K, R, 0);
        assert_eq!(t.len(), 3);
        // Restore middle page's protection — should coalesce into one.
        t.change_protection(K, 2 * K, RW, 0);
        assert_eq!(t.len(), 1);
        let only = t.iter().next().unwrap();
        assert_eq!((only.start, only.end), (0, 3 * K));
    }

    #[test]
    fn change_protection_splits_at_boundaries() {
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, 4 * K, RW, obj, 0));
        t.change_protection(K, 3 * K, R, 0);
        let vs: alloc::vec::Vec<_> = t
            .iter()
            .map(|v| (v.start, v.end, v.prot_user, v.object_offset))
            .collect();
        assert_eq!(
            vs,
            [(0, K, RW, 0), (K, 3 * K, R, K), (3 * K, 4 * K, RW, 3 * K),],
        );
    }

    #[test]
    fn change_protection_coalesces_multiple_affected() {
        // Regression: Pass 3 must not panic when `insert` forward-merges
        // consumes a later key from the `affected` list.
        let obj = stub();
        let mut t = VmaTree::new();
        // Three adjacent VMAs with distinct prots so nothing merges.
        t.insert(vma(0, K, RW, Arc::clone(&obj), 0));
        t.insert(vma(K, 2 * K, R, Arc::clone(&obj), K));
        t.insert(vma(2 * K, 3 * K, RW, obj, 2 * K));
        assert_eq!(t.len(), 3);
        // Rewrite the whole span to a uniform prot — all three become
        // mergeable after Pass 2, and Pass 3 must coalesce without
        // panicking on the already-consumed keys.
        t.change_protection(0, 3 * K, RW, 0);
        assert_eq!(t.len(), 1);
        let only = t.iter().next().unwrap();
        assert_eq!((only.start, only.end), (0, 3 * K));
    }

    #[test]
    fn change_protection_merges_with_non_affected_right_neighbour() {
        // Regression: with an even number of affected VMAs, Pass 3's
        // leap-frog re-insertion could consume every affected key via
        // forward-merge without ever touching the non-affected right
        // neighbour. The surviving VMA must still coalesce with it.
        let obj = stub();
        let mut t = VmaTree::new();
        t.insert(vma(0, K, RW, Arc::clone(&obj), 0));
        t.insert(vma(K, 2 * K, R, Arc::clone(&obj), K));
        t.insert(vma(2 * K, 3 * K, R, Arc::clone(&obj), 2 * K));
        t.insert(vma(3 * K, 4 * K, RW, obj, 3 * K));
        assert_eq!(t.len(), 3); // middle two coalesce: RW, R(2K), RW
                                // Restore the middle to RW: all four become one.
        t.change_protection(K, 3 * K, RW, 0);
        assert_eq!(t.len(), 1);
        let only = t.iter().next().unwrap();
        assert_eq!((only.start, only.end), (0, 4 * K));
    }

    #[test]
    fn anon_object_backed_vma_compiles() {
        // Sanity: the real `AnonObject` slots into `Vma::object` without
        // needing a stub.
        let obj: Arc<dyn VmObject> = AnonObject::new(Some(4));
        let mut t = VmaTree::new();
        t.insert(vma(0, 2 * K, RW, obj, 0));
        assert_eq!(t.len(), 1);
    }
}
