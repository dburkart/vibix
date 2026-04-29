//! `VmObject`: the polymorphism point for "what backs this VMA?" Lives
//! behind an `Arc<dyn VmObject>` so future file-backed and
//! phys-borrowed mappings can slot in without touching the page-fault
//! resolver or the VMA tree.
//!
//! Today's only implementation is [`AnonObject`] — the zero-fill-on-
//! first-touch backing used by heap, stack, and anonymous mmap regions.
//! It caches every allocated frame in a sparse `BTreeMap<page_index,
//! phys_addr>` so a second fault against the same offset returns the
//! same frame (required by mprotect and the CoW resolver). Drop walks
//! the cache and drops one refcount per frame, reclaiming those that
//! reach zero.
//!
//! See RFC 0001 "Userspace Virtual Memory Subsystem" for the trait
//! shape, the CoW interaction contract, and the `PageRefcount`
//! invariants this module relies on.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use spin::Mutex;

use crate::mem::FRAME_SIZE;

/// The kind of access that triggered a fault. Passed to
/// [`VmObject::fault`] so implementations that care (future
/// `FileObject` with PROT_WRITE-on-private-mapping) can distinguish
/// read- from write-faults.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
}

/// Why a [`VmObject::fault`] call failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmFault {
    /// The frame allocator is empty.
    OutOfMemory,
    /// Offset is past the end of a bounded object.
    OutOfRange,
    /// Access kind not allowed by this object (e.g. future read-only
    /// file mapping being written). Unused today but reserved so the
    /// resolver has one shape to match against.
    ProtectionViolation,
    /// The target frame's refcount is pinned at `u16::MAX`; adding
    /// another reference would violate RFC 0001's exact-or-over
    /// invariant and risk a UAF on the matching drop. Produced by the
    /// cache-hit path in [`AnonObject::fault`] when the shared frame is
    /// already maximally-referenced.
    RefcountSaturated,
    /// `FileObject` write fault on a `Share::Private` mapping. The
    /// resolver upgrades the PTE through `cow_copy_and_remap` exactly
    /// the way a fork-induced CoW does today (RFC 0007 §FileObject,
    /// §Algorithms — `MAP_PRIVATE` on a write fault). Threading this
    /// sentinel through the page-fault resolver is tracked under
    /// #739; the variant is added here so `FileObject::fault` can
    /// return it without depending on the resolver wiring.
    CoWNeeded,
    /// The faulter must park on the [`crate::mem::page_cache::CachePage`]
    /// wait-queue and retry the slow path. Surfaced when the cache
    /// install-race loser observes a stub whose filler errored — the
    /// stub is removed from the index and waiters retry against a
    /// fresh fill (RFC 0007 §Algorithms — `FileObject::fault` slow
    /// path). Resolver wiring is #739.
    ParkAndRetry,
    /// `AddressSpaceOps::readpage` returned an errno. The faulter is
    /// the one task that observed the failed fill — by contract the
    /// stub has already been removed from the cache index and other
    /// waiters have been woken to retry. The errno is the kernel's
    /// negative-i64 convention (e.g. `crate::fs::EIO`); resolver
    /// wiring (#739) will translate it to SIGBUS / SIGSEGV per the
    /// existing error table.
    ReadFailed(i64),
}

/// Polymorphic "what backs this VMA" trait. Lives behind
/// `Arc<dyn VmObject>` so the VMA tree can hold any concrete
/// implementation without compile-time dispatch.
pub trait VmObject: Send + Sync {
    /// Resolve the frame backing `offset` (page-aligned bytes into this
    /// object), allocating lazily if necessary. The returned physical
    /// address is owned by the object — the caller maps it into its
    /// page table but does not own a reference count of its own unless
    /// it explicitly `inc_refcount`s.
    fn fault(&self, offset: usize, access: Access) -> Result<u64, VmFault>;

    /// Number of pages this object covers. `None` for unbounded
    /// (heap-style) objects.
    fn len_pages(&self) -> Option<usize>;

    /// Return the cached physical address for `offset` without allocating,
    /// or `None` if the page has not been faulted in yet.
    ///
    /// Used by `reap_pending` to detect private CoW copies: after
    /// `cow_copy_and_remap` the PTE holds a new private frame that is
    /// *not* in this object's cache (the cache still maps the offset to
    /// the original source frame). When the PTE frame differs from this
    /// return value, `reap_pending` frees it directly; the cached source
    /// frame is freed later by [`Drop`]. Implementations that do not
    /// cache frames (future file-backed objects) return `None`, which
    /// triggers the same "free the PTE frame directly" path — safe because
    /// those objects never own the frame in the first place.
    fn frame_at(&self, offset: usize) -> Option<u64> {
        let _ = offset;
        None
    }

    /// Return a fresh backing object for a `Share::Private` fork child.
    ///
    /// Called by `fork_address_space` for every Private VMA so post-fork
    /// demand faults on unfaulted pages allocate **independent** frames in
    /// parent and child. `AnonObject` returns a new empty cache with the
    /// same `len_pages` bound; future file-backed objects should return a
    /// similarly independent copy.
    fn clone_private(&self) -> Arc<dyn VmObject>;

    /// Release cached frames for all page indices ≥ `from_page`. Called
    /// by `sys_brk` during heap shrink so stale frames are freed promptly
    /// rather than waiting until the object is dropped. The default is a
    /// no-op; `AnonObject` overrides it to trim its frame cache.
    fn truncate_from_page(&self, _from_page: usize) {}

    /// Release cached frames for page indices in `[first, last)`. Called
    /// by `madvise(MADV_DONTNEED)` so the next fault returns a fresh
    /// zero-filled frame instead of the one previously cached. Default
    /// is a no-op; `AnonObject` overrides to evict the range.
    fn evict_range(&self, _first: usize, _last: usize) {}
}

/// Clone a `VmObject` trait-object for `fork`. The default behavior is
/// `Arc::clone` — child and parent share backing frames via the
/// page-refcount mechanism, and CoW is resolved at the PTE layer, not
/// here. A concrete `VmObject` that needs a deep clone on fork (future
/// writable shared-memory segments, for example) can expose its own
/// type-specific helper and upcast to `Arc<dyn VmObject>`.
pub fn clone_for_fork(obj: &Arc<dyn VmObject>) -> Arc<dyn VmObject> {
    Arc::clone(obj)
}

/// Zero-fill anonymous object.
pub struct AnonObject {
    inner: Mutex<AnonInner>,
    len_pages: Option<usize>,
}

struct AnonInner {
    /// Sparse cache of already-allocated pages. Key: page index
    /// (`offset / FRAME_SIZE`). Value: physical address.
    frames: BTreeMap<usize, u64>,
}

impl AnonObject {
    /// Create a new anonymous object.
    ///
    /// `len_pages = None` means unbounded (the brk/heap style). Most
    /// fixed-size mmap mappings pass `Some(n)`; faults past the cap
    /// return [`VmFault::OutOfRange`].
    pub fn new(len_pages: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(AnonInner {
                frames: BTreeMap::new(),
            }),
            len_pages,
        })
    }

    /// Bounds-check a page-aligned `offset` against `len_pages`. Pulled
    /// out of `fault` so host tests can exercise it without touching
    /// the frame allocator.
    fn check_bounds(&self, offset: usize) -> Result<usize, VmFault> {
        assert!(
            offset % (FRAME_SIZE as usize) == 0,
            "AnonObject::fault: offset {offset:#x} is not page-aligned",
        );
        let idx = offset / (FRAME_SIZE as usize);
        if let Some(cap) = self.len_pages {
            if idx >= cap {
                return Err(VmFault::OutOfRange);
            }
        }
        Ok(idx)
    }
}

impl VmObject for AnonObject {
    fn fault(&self, offset: usize, _access: Access) -> Result<u64, VmFault> {
        let idx = self.check_bounds(offset)?;
        let mut inner = self.inner.lock();
        if let Some(&frame) = inner.frames.get(&idx) {
            // Increment for the new PTE mapping. Every installed PTE holds
            // one reference; the cache entry holds a separate reference.
            // Balanced by `frame::put` in `AddressSpace::drop` when the
            // PTE is removed (or `cow_copy_and_remap` when CoW resolves it).
            //
            // Checked increment: if the slot is pinned at `u16::MAX`
            // another shared fault would violate RFC 0001's
            // exact-or-over invariant and UAF on the matching drop.
            // Refuse the fault instead of publishing the new reference.
            #[cfg(target_os = "none")]
            crate::mem::refcount::try_inc_refcount(frame)
                .map_err(|_| VmFault::RefcountSaturated)?;
            return Ok(frame);
        }
        let phys = alloc_zeroed_page()?;
        inner.frames.insert(idx, phys);
        // `alloc_zeroed_page` sets refcount=1 (the cache's reference).
        // Increment once more for the PTE mapping being installed by caller.
        //
        // Saturation is impossible here: the frame was just allocated and
        // its refcount is 1. Use the checked variant for consistency with
        // the cache-hit path and panic on the invariant violation rather
        // than silently saturating.
        #[cfg(target_os = "none")]
        crate::mem::refcount::try_inc_refcount(phys)
            .expect("freshly-allocated frame cannot be at u16::MAX");
        Ok(phys)
    }

    fn len_pages(&self) -> Option<usize> {
        self.len_pages
    }

    fn frame_at(&self, offset: usize) -> Option<u64> {
        let idx = offset / (crate::mem::FRAME_SIZE as usize);
        self.inner.lock().frames.get(&idx).copied()
    }

    fn clone_private(&self) -> Arc<dyn VmObject> {
        // Return a fresh empty `AnonObject` with the same size bound.
        // Post-fork demand faults on unfaulted pages will allocate
        // independent frames in the child; already-W-stripped frames are
        // handled entirely at the PTE layer by `fork_address_space` and
        // need no entry in this cache.
        Arc::new(Self {
            inner: Mutex::new(AnonInner {
                frames: BTreeMap::new(),
            }),
            len_pages: self.len_pages,
        })
    }

    fn truncate_from_page(&self, from_page: usize) {
        #[cfg(target_os = "none")]
        self.truncate_cache(from_page);
        #[cfg(not(target_os = "none"))]
        let _ = from_page;
    }

    fn evict_range(&self, first: usize, last: usize) {
        #[cfg(target_os = "none")]
        self.evict_cache_range(first, last);
        #[cfg(not(target_os = "none"))]
        {
            let _ = (first, last);
        }
    }
}

/// Kernel-only methods on `AnonObject`.
#[cfg(target_os = "none")]
impl AnonObject {
    /// Insert `phys` into the frame cache at page index `idx` and
    /// increment its refcount by one for the cache's ownership.
    ///
    /// Use this when frames are pre-mapped into a PML4 by an external
    /// loader (e.g. `load_user_elf`) and you want to retroactively
    /// register them in an `AnonObject` so the VMA machinery can track
    /// and fork them correctly.
    ///
    /// The caller must ensure that `phys` already has a PTE reference
    /// (refcount ≥ 1). This method adds the cache reference on top.
    ///
    /// Returns `Err(Saturated)` if `phys`'s refcount is already pinned
    /// at `u16::MAX`. On error the frame is **not** inserted into the
    /// cache, so no orphan reference is published. Today every caller
    /// passes a freshly-allocated frame whose refcount is 1, so the
    /// error is unreachable in practice — the fallible signature makes
    /// the RFC 0001 exact-or-over invariant statically enforced should
    /// that ever change.
    pub fn insert_existing_frame(
        &self,
        idx: usize,
        phys: u64,
    ) -> Result<(), crate::mem::refcount::Saturated> {
        // Bump the cache's reference first: if the slot is saturated we
        // return before touching the BTreeMap, so no dangling cache
        // entry references a frame whose refcount we failed to claim.
        crate::mem::refcount::try_inc_refcount(phys)?;
        self.inner.lock().frames.insert(idx, phys);
        Ok(())
    }

    /// Remove cached frames whose page index is in `[first, last)` and
    /// release their cache references. Used by
    /// `madvise(MADV_DONTNEED)` — the next fault on an evicted index
    /// allocates a fresh zero-filled frame.
    pub fn evict_cache_range(&self, first: usize, last: usize) {
        let evicted: alloc::vec::Vec<(usize, u64)> = {
            let mut inner = self.inner.lock();
            let keys: alloc::vec::Vec<usize> =
                inner.frames.range(first..last).map(|(&k, _)| k).collect();
            keys.into_iter()
                .filter_map(|k| inner.frames.remove(&k).map(|v| (k, v)))
                .collect()
        };
        for (_, phys) in evicted {
            crate::mem::frame::put(phys);
        }
    }

    /// Remove all cached frames whose page index is ≥ `from_page` and
    /// release their cache references. Used by `sys_brk` when the heap
    /// is shrunk so memory is not pinned until process exit.
    pub fn truncate_cache(&self, from_page: usize) {
        let evicted: alloc::vec::Vec<(usize, u64)> = {
            let mut inner = self.inner.lock();
            let keys: alloc::vec::Vec<usize> =
                inner.frames.range(from_page..).map(|(&k, _)| k).collect();
            keys.into_iter()
                .filter_map(|k| inner.frames.remove(&k).map(|v| (k, v)))
                .collect()
        };
        // Release cache references outside the lock so `frame::put` can
        // re-enter the allocator without a spinlock collision.
        for (_, phys) in evicted {
            crate::mem::frame::put(phys);
        }
    }
}

impl Drop for AnonObject {
    fn drop(&mut self) {
        let frames = core::mem::take(&mut self.inner.get_mut().frames);
        for (_idx, phys) in frames {
            release_frame(phys);
        }
    }
}

// --- Frame allocation helpers ------------------------------------------

/// Allocate a page-sized physical frame and zero it through the HHDM.
/// Returns the physical address. The allocator has already set the
/// frame's refcount to 1.
#[cfg(target_os = "none")]
fn alloc_zeroed_page() -> Result<u64, VmFault> {
    let phys = crate::mem::frame::alloc().ok_or(VmFault::OutOfMemory)?;
    let hhdm = crate::mem::paging::hhdm_offset().as_u64();
    // SAFETY: `phys` was just allocated for us, is 4 KiB-aligned, and
    // covered by the HHDM mapping. Exclusive ownership until insertion
    // into the cache, so no aliasing writer exists for this zero.
    unsafe {
        core::ptr::write_bytes((hhdm + phys) as *mut u8, 0, FRAME_SIZE as usize);
    }
    Ok(phys)
}

#[cfg(target_os = "none")]
fn release_frame(phys: u64) {
    crate::mem::frame::put(phys);
}

// On host, `fault` never falls through to `alloc_zeroed_page` in the tests
// exercised here (they either pre-populate the cache or hit the bounds
// check first). Provide a stub so the crate compiles for `cargo test` on
// the host; any accidental invocation surfaces as an explicit panic
// rather than a link error.
#[cfg(not(target_os = "none"))]
fn alloc_zeroed_page() -> Result<u64, VmFault> {
    panic!("AnonObject::fault on host without HOST_FRAME_SOURCE set up");
}

#[cfg(not(target_os = "none"))]
fn release_frame(_phys: u64) {
    #[cfg(test)]
    tests::HOST_RELEASE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
impl AnonObject {
    /// Test-only: inject a synthetic frame address for page `idx` so
    /// host unit tests can exercise the cache-hit fast path and the
    /// bounds check without going through the frame allocator.
    pub(crate) fn insert_for_test(&self, idx: usize, phys: u64) {
        self.inner.lock().frames.insert(idx, phys);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// Incremented by the host stub of [`release_frame`] each time `Drop`
    /// calls it. Observed only by [`drop_releases_every_cached_frame`]
    /// and serialised via [`release_test_lock`] so the delta is
    /// deterministic even under `cargo test`'s parallel harness.
    pub(super) static HOST_RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Serialises every host test whose body drops an `AnonObject` that
    /// still holds synthetic frames. The observer test takes this lock
    /// and resets the counter under it; other tests hold it for the
    /// span of their own drops so their `release_frame` calls never
    /// leak into the observer's delta.
    fn release_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        // `unwrap_or_else` keeps a prior panicked test from poisoning
        // the rest of the suite; the `()` guard carries no state.
        LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn cached_fault_returns_same_frame() {
        let _g = release_test_lock();
        let obj = AnonObject::new(Some(8));
        obj.insert_for_test(3, 0x1234_5000);
        let p = obj.fault(3 * 4096, Access::Read).unwrap();
        assert_eq!(p, 0x1234_5000);
        // Second lookup returns the same cached frame.
        let p2 = obj.fault(3 * 4096, Access::Write).unwrap();
        assert_eq!(p2, 0x1234_5000);
    }

    #[test]
    fn fault_past_bound_returns_out_of_range() {
        // No cached frames, so no release_frame traffic; skip the lock.
        let obj = AnonObject::new(Some(4));
        let err = obj.fault(4 * 4096, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::OutOfRange);
        // Also one past the last legal page.
        let err = obj.fault(100 * 4096, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::OutOfRange);
    }

    #[test]
    fn fault_at_last_page_is_legal() {
        let _g = release_test_lock();
        let obj = AnonObject::new(Some(4));
        obj.insert_for_test(3, 0xdead_0000);
        let p = obj.fault(3 * 4096, Access::Read).unwrap();
        assert_eq!(p, 0xdead_0000);
    }

    #[test]
    fn unbounded_object_accepts_any_offset() {
        let _g = release_test_lock();
        let obj = AnonObject::new(None);
        obj.insert_for_test(1_000_000, 0xabcd_0000);
        let p = obj.fault(1_000_000 * 4096, Access::Read).unwrap();
        assert_eq!(p, 0xabcd_0000);
    }

    #[test]
    fn len_pages_roundtrips() {
        assert_eq!(AnonObject::new(Some(7)).len_pages(), Some(7));
        assert_eq!(AnonObject::new(None).len_pages(), None);
    }

    #[test]
    #[should_panic(expected = "not page-aligned")]
    fn unaligned_offset_panics() {
        let obj = AnonObject::new(None);
        let _ = obj.fault(0x1001, Access::Read);
    }

    #[test]
    fn clone_for_fork_shares_cache() {
        let _g = release_test_lock();
        // `clone_for_fork` (the free function) performs an Arc::clone —
        // used for Share::Shared VMAs. The forked Arc sees the same
        // cached frames as the parent (sharing is intentional for Shared).
        let anon = AnonObject::new(Some(4));
        anon.insert_for_test(0, 0x4000);
        let parent: Arc<dyn VmObject> = anon;
        let forked = clone_for_fork(&parent);
        assert_eq!(forked.fault(0, Access::Read).unwrap(), 0x4000);
    }

    #[test]
    fn clone_private_produces_empty_independent_object() {
        let _g = release_test_lock();
        // clone_private (used for Share::Private VMAs) must return a new
        // object with an empty cache so post-fork demand faults in parent
        // and child allocate independent frames.
        let anon = AnonObject::new(Some(4));
        anon.insert_for_test(0, 0x4000);
        anon.insert_for_test(1, 0x5000);
        let parent: Arc<dyn VmObject> = anon;
        let child = parent.clone_private();
        // Child cache is empty — frame_at returns None for every offset.
        assert_eq!(child.frame_at(0), None);
        assert_eq!(child.frame_at(4096), None);
        // Child is a distinct allocation.
        assert!(!core::ptr::addr_eq(
            Arc::as_ptr(&parent) as *const (),
            Arc::as_ptr(&(child as Arc<dyn VmObject>)) as *const ()
        ));
    }

    #[test]
    fn clone_private_preserves_len_pages() {
        let _g = release_test_lock();
        let parent: Arc<dyn VmObject> = AnonObject::new(Some(8));
        let child = parent.clone_private();
        assert_eq!(child.len_pages(), Some(8));

        let unbounded: Arc<dyn VmObject> = AnonObject::new(None);
        let child2 = unbounded.clone_private();
        assert_eq!(child2.len_pages(), None);
    }

    #[test]
    fn drop_releases_every_cached_frame() {
        let _g = release_test_lock();
        // Seed three cached frames, drop the object, confirm
        // `release_frame` was invoked once per frame.
        let before = HOST_RELEASE_COUNT.load(Ordering::Relaxed);
        {
            let obj = AnonObject::new(Some(8));
            obj.insert_for_test(0, 0x1000);
            obj.insert_for_test(1, 0x2000);
            obj.insert_for_test(5, 0x5000);
        }
        let after = HOST_RELEASE_COUNT.load(Ordering::Relaxed);
        assert_eq!(after - before, 3);
    }
}
