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

    /// Clone this object for `fork`. The default is `Arc::clone` —
    /// callers share backing frames via the page-refcount mechanism,
    /// and CoW is resolved at the PTE layer, not here.
    fn clone_for_fork(self: Arc<Self>) -> Arc<dyn VmObject>
    where
        Self: Sized + 'static,
    {
        self
    }
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
            return Ok(frame);
        }
        let phys = alloc_zeroed_page()?;
        inner.frames.insert(idx, phys);
        Ok(phys)
    }

    fn len_pages(&self) -> Option<usize> {
        self.len_pages
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
    // Host tests that install synthetic frames via
    // `AnonObject::insert_for_test` are responsible for clearing the map
    // before drop.
}

#[cfg(test)]
impl AnonObject {
    /// Test-only: inject a synthetic frame address for page `idx` so
    /// host unit tests can exercise the cache-hit fast path and the
    /// bounds check without going through the frame allocator.
    pub(crate) fn insert_for_test(&self, idx: usize, phys: u64) {
        self.inner.lock().frames.insert(idx, phys);
    }

    /// Test-only: clear the cache without dropping any frames. Called
    /// by host tests before `drop` so the stub `release_frame` doesn't
    /// need to know how to account for synthetic frames.
    pub(crate) fn forget_all_for_test(&self) {
        self.inner.lock().frames.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_fault_returns_same_frame() {
        let obj = AnonObject::new(Some(8));
        obj.insert_for_test(3, 0x1234_5000);
        let p = obj.fault(3 * 4096, Access::Read).unwrap();
        assert_eq!(p, 0x1234_5000);
        // Second lookup returns the same cached frame.
        let p2 = obj.fault(3 * 4096, Access::Write).unwrap();
        assert_eq!(p2, 0x1234_5000);
        obj.forget_all_for_test();
    }

    #[test]
    fn fault_past_bound_returns_out_of_range() {
        let obj = AnonObject::new(Some(4));
        let err = obj.fault(4 * 4096, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::OutOfRange);
        // Also one past the last legal page.
        let err = obj.fault(100 * 4096, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::OutOfRange);
    }

    #[test]
    fn fault_at_last_page_is_legal() {
        let obj = AnonObject::new(Some(4));
        obj.insert_for_test(3, 0xdead_0000);
        let p = obj.fault(3 * 4096, Access::Read).unwrap();
        assert_eq!(p, 0xdead_0000);
        obj.forget_all_for_test();
    }

    #[test]
    fn unbounded_object_accepts_any_offset() {
        let obj = AnonObject::new(None);
        obj.insert_for_test(1_000_000, 0xabcd_0000);
        let p = obj.fault(1_000_000 * 4096, Access::Read).unwrap();
        assert_eq!(p, 0xabcd_0000);
        obj.forget_all_for_test();
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
        // Arc-clone is the default; the forked object sees the same
        // cached frames as the parent until the CoW path diverges them
        // at the PTE layer.
        let obj = AnonObject::new(Some(4));
        obj.insert_for_test(0, 0x4000);
        let forked = obj.clone().clone_for_fork();
        assert_eq!(forked.fault(0, Access::Read).unwrap(), 0x4000);
        obj.forget_all_for_test();
    }
}
