//! Per-frame refcount array. The foundation for copy-on-write, `fork`,
//! and address-space teardown (RFC 0001).
//!
//! One `AtomicU16` per 4 KiB physical frame. At `MAX_PHYS_BYTES = 4 GiB`
//! that's 1,048,576 entries × 2 bytes = 2 MiB of `.bss`. The allocator
//! stores `1` on hand-out; `inc_refcount` bumps on share (e.g. `fork`'s
//! W-strip); `dec_refcount` drops on unmap; `frame_free` asserts `0`
//! before reclaim.
//!
//! **Invariant:** the refcount is **exact or over-approximated** — it
//! is never under-approximated. Saturation at `u16::MAX` is a permanent
//! over-approximation (callers detect saturation via the return value
//! of `inc_refcount` and fall back to eager copy rather than CoW).
//!
//! Kept free of `x86_64`/`limine` types so the logic can be unit-tested
//! on the host against an explicit slice; the kernel-facing entry points
//! are `#[cfg(target_os = "none")]` wrappers over a module-private
//! static array.

use core::sync::atomic::{AtomicU16, Ordering};

use super::frame::MAX_PHYS_BYTES;
use super::FRAME_SIZE;

/// Number of refcount slots tracked. One per 4 KiB frame in
/// `[0, MAX_PHYS_BYTES)`.
pub const REFCOUNT_LEN: usize = (MAX_PHYS_BYTES / FRAME_SIZE) as usize;

#[cfg(target_os = "none")]
static REFCOUNTS: [AtomicU16; REFCOUNT_LEN] = [const { AtomicU16::new(0) }; REFCOUNT_LEN];

fn index_of(phys: u64) -> usize {
    assert!(
        phys & (FRAME_SIZE - 1) == 0,
        "refcount: {phys:#x} is not frame-aligned",
    );
    let idx = (phys / FRAME_SIZE) as usize;
    assert!(
        idx < REFCOUNT_LEN,
        "refcount: {phys:#x} is above MAX_PHYS_BYTES",
    );
    idx
}

// --- Pure helpers over an explicit slice, host-testable. ---------------

/// Borrow the refcount slot for `phys` from `slots`. `phys` must be
/// frame-aligned, `< MAX_PHYS_BYTES`, and within the slice's own bounds
/// (so host tests against a tiny table still produce a refcount-specific
/// panic message instead of a generic slice OOB).
pub fn page_refcount_in(slots: &[AtomicU16], phys: u64) -> &AtomicU16 {
    let idx = index_of(phys);
    assert!(
        idx < slots.len(),
        "refcount: {phys:#x} is outside the provided refcount table",
    );
    &slots[idx]
}

/// Saturating fetch-add of 1. Returns the previous value. Once a slot
/// reaches `u16::MAX` it is pinned there — further increments are
/// no-ops, preserving the "exact-or-over" invariant. Callers that need
/// to distinguish a real share from a saturated over-approximation
/// compare the return value against `u16::MAX - 1` / `u16::MAX`.
pub fn inc_refcount_in(slots: &[AtomicU16], phys: u64) -> u16 {
    let slot = page_refcount_in(slots, phys);
    let mut cur = slot.load(Ordering::Relaxed);
    loop {
        if cur == u16::MAX {
            return u16::MAX;
        }
        match slot.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(prev) => return prev,
            Err(observed) => cur = observed,
        }
    }
}

/// Checked `fetch_sub(1, Release)`. Panics on underflow (refcount
/// already zero). Returns the previous value; callers use
/// `prev == 1` to detect "we just brought this frame to zero — it may
/// now be freed." `Release` ordering pairs with the `Acquire` fence
/// the caller issues before handing the frame back to the allocator.
pub fn dec_refcount_in(slots: &[AtomicU16], phys: u64) -> u16 {
    let slot = page_refcount_in(slots, phys);
    let prev = slot.fetch_sub(1, Ordering::Release);
    assert!(prev > 0, "refcount: decrement underflow at {phys:#x}",);
    prev
}

/// Called by the frame allocator at hand-out. Stores `1` and asserts
/// the previous value was `0`. A non-zero prior value means either the
/// allocator handed the same frame out twice, or a previous caller
/// failed to bring the refcount to zero before freeing it.
pub fn init_on_alloc_in(slots: &[AtomicU16], phys: u64) {
    let slot = page_refcount_in(slots, phys);
    let prev = slot.swap(1, Ordering::Relaxed);
    assert_eq!(
        prev, 0,
        "refcount: alloc of {phys:#x} found pre-existing refcount {prev}",
    );
}

/// Called by the frame allocator before reclaim. Panics if the slot is
/// not `0`, catching callers that free a frame with live references.
pub fn assert_zero_for_free_in(slots: &[AtomicU16], phys: u64) {
    let slot = page_refcount_in(slots, phys);
    let cur = slot.load(Ordering::Relaxed);
    assert_eq!(
        cur, 0,
        "refcount: free of {phys:#x} with non-zero refcount {cur}",
    );
}

// --- Global (kernel-only) entry points over the static table. ----------

/// Borrow the global refcount slot for `phys`.
#[cfg(target_os = "none")]
pub fn page_refcount(phys: u64) -> &'static AtomicU16 {
    page_refcount_in(&REFCOUNTS, phys)
}

/// Saturating increment of the global slot for `phys`. See
/// [`inc_refcount_in`] for semantics.
#[cfg(target_os = "none")]
pub fn inc_refcount(phys: u64) -> u16 {
    inc_refcount_in(&REFCOUNTS, phys)
}

/// Checked decrement of the global slot for `phys`. See
/// [`dec_refcount_in`] for semantics.
#[cfg(target_os = "none")]
pub fn dec_refcount(phys: u64) -> u16 {
    dec_refcount_in(&REFCOUNTS, phys)
}

#[cfg(target_os = "none")]
pub(super) fn init_on_alloc(phys: u64) {
    init_on_alloc_in(&REFCOUNTS, phys)
}

#[cfg(target_os = "none")]
pub(super) fn assert_zero_for_free(phys: u64) {
    assert_zero_for_free_in(&REFCOUNTS, phys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(n: usize) -> Vec<AtomicU16> {
        (0..n).map(|_| AtomicU16::new(0)).collect()
    }

    #[test]
    fn alloc_initialises_to_one() {
        let t = mk(8);
        init_on_alloc_in(&t, 0x1000);
        assert_eq!(page_refcount_in(&t, 0x1000).load(Ordering::Relaxed), 1);
    }

    #[test]
    fn double_inc_yields_three() {
        let t = mk(8);
        init_on_alloc_in(&t, 0x1000);
        assert_eq!(inc_refcount_in(&t, 0x1000), 1); // 1 -> 2
        assert_eq!(inc_refcount_in(&t, 0x1000), 2); // 2 -> 3
        assert_eq!(page_refcount_in(&t, 0x1000).load(Ordering::Relaxed), 3);
    }

    #[test]
    fn dec_returns_previous() {
        let t = mk(8);
        init_on_alloc_in(&t, 0x1000);
        inc_refcount_in(&t, 0x1000); // 1 -> 2
        inc_refcount_in(&t, 0x1000); // 2 -> 3
        assert_eq!(dec_refcount_in(&t, 0x1000), 3); // 3 -> 2
        assert_eq!(dec_refcount_in(&t, 0x1000), 2); // 2 -> 1
        assert_eq!(dec_refcount_in(&t, 0x1000), 1); // 1 -> 0
        assert_eq!(page_refcount_in(&t, 0x1000).load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dec_to_zero_then_free_is_ok() {
        let t = mk(4);
        init_on_alloc_in(&t, 0x1000);
        assert_eq!(dec_refcount_in(&t, 0x1000), 1); // 1 -> 0
        assert_zero_for_free_in(&t, 0x1000);
    }

    #[test]
    fn inc_saturates_at_u16_max() {
        let t = mk(4);
        page_refcount_in(&t, 0x2000).store(u16::MAX - 1, Ordering::Relaxed);
        assert_eq!(inc_refcount_in(&t, 0x2000), u16::MAX - 1); // -> MAX
        assert_eq!(inc_refcount_in(&t, 0x2000), u16::MAX); // pinned
        assert_eq!(
            page_refcount_in(&t, 0x2000).load(Ordering::Relaxed),
            u16::MAX,
        );
    }

    #[test]
    #[should_panic(expected = "non-zero refcount")]
    fn free_with_nonzero_refcount_panics() {
        let t = mk(4);
        init_on_alloc_in(&t, 0x1000); // refcount = 1
        assert_zero_for_free_in(&t, 0x1000);
    }

    #[test]
    #[should_panic(expected = "decrement underflow")]
    fn dec_below_zero_panics() {
        let t = mk(4);
        dec_refcount_in(&t, 0x1000);
    }

    #[test]
    #[should_panic(expected = "pre-existing refcount")]
    fn alloc_over_nonzero_panics() {
        let t = mk(4);
        init_on_alloc_in(&t, 0x1000);
        init_on_alloc_in(&t, 0x1000);
    }

    #[test]
    #[should_panic(expected = "not frame-aligned")]
    fn unaligned_address_panics() {
        let t = mk(4);
        page_refcount_in(&t, 0x1001);
    }

    #[test]
    #[should_panic(expected = "above MAX_PHYS_BYTES")]
    fn out_of_range_panics() {
        let t = mk(4);
        page_refcount_in(&t, MAX_PHYS_BYTES);
    }
}
