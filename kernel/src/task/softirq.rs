//! Soft-IRQ (bottom-half) primitive per RFC 0003.
//!
//! Hardware ISRs stay tiny: touch device state, EOI, return. Any work
//! that can run later — parsing a scancode, pulling bytes through a
//! line discipline, poking a waitqueue — is deferred here. The ISR
//! calls [`raise`] to latch a bit into the pending mask; the drain
//! runs at the tail of [`crate::task::preempt_tick`] and invokes the
//! registered handler for every set bit.
//!
//! Design choices for a single-CPU kernel:
//!
//! - Pending bits live in a single `AtomicU32`. `raise` is a lock-free
//!   `fetch_or`, safe from ISR context.
//! - The handler table is a fixed array of `AtomicPtr` keyed by vector
//!   index. `register` is expected at init time; calling it from a
//!   running system is tolerated but racy (a `raise` between the
//!   pending-set and pointer-store can drop the event, matching
//!   Linux's own "register before enabling the IRQ" convention).
//! - Handlers run with IRQs masked, on whatever kernel stack the
//!   drainer ran on (today: the interrupted task's stack via
//!   `preempt_tick`). Must be O(1) stack. Re-raising inside a handler
//!   re-sets the pending bit and is picked up on the next tick — the
//!   latch is atomic, so no re-entry guard is needed as long as the
//!   drainer runs IRQ-off.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// Soft-IRQ vectors. Keep small; each adds a pending bit and a handler
/// slot. Discriminants double as the bit index in [`PENDING`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SoftIrq {
    SerialRx = 0,
    PS2Rx = 1,
    /// Reserved for future wiring. Keeps the table a stable size so
    /// tests can rely on indices without churn.
    Reserved2 = 2,
    Reserved3 = 3,
}

impl SoftIrq {
    const fn index(self) -> usize {
        self as usize
    }

    const fn bit(self) -> u32 {
        1u32 << (self as u8)
    }
}

const NUM_VECTORS: usize = 4;

static PENDING: AtomicU32 = AtomicU32::new(0);

static HANDLERS: [AtomicPtr<()>; NUM_VECTORS] = [
    AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()),
];

/// Latch a pending bit for `vec`. Safe from ISR context.
pub fn raise(vec: SoftIrq) {
    PENDING.fetch_or(vec.bit(), Ordering::Release);
}

/// Register the handler for `vec`. Intended to be called at init,
/// before the corresponding IRQ source is unmasked. Replacing a
/// handler at runtime is allowed but carries the race noted in the
/// module docs.
pub fn register(vec: SoftIrq, handler: fn()) {
    HANDLERS[vec.index()].store(handler as *mut (), Ordering::Release);
}

/// Drain the pending mask: for each set bit, clear it, look up the
/// handler, and invoke it. Must run with IRQs masked. Safe to call
/// when nothing is pending (cheap: one atomic load + branch).
pub fn drain() {
    loop {
        let pending = PENDING.swap(0, Ordering::AcqRel);
        if pending == 0 {
            return;
        }
        let mut mask = pending;
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            if bit >= NUM_VECTORS {
                continue;
            }
            let raw = HANDLERS[bit].load(Ordering::Acquire);
            if raw.is_null() {
                continue;
            }
            // SAFETY: `register` only ever stores values obtained from
            // `fn() as *mut ()`. Converting back yields the original
            // function pointer. Null was filtered above.
            let handler: fn() = unsafe { core::mem::transmute::<*mut (), fn()>(raw) };
            handler();
        }
        // Loop once more in case a handler re-raised its own bit or
        // another vector fired during handler execution. Bounded by
        // the number of distinct vectors times whatever latch rate
        // handlers produce; callers are expected to make progress.
    }
}

/// Clear all pending bits and registered handlers. Intended for
/// integration tests that want a clean slate between cases.
pub fn reset_for_test() {
    PENDING.store(0, Ordering::Release);
    for h in HANDLERS.iter() {
        h.store(core::ptr::null_mut(), Ordering::Release);
    }
}
