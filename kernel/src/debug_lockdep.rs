//! Minimal debug-build lockdep tripwire — tracks the count of
//! kernel spinlocks currently held by the caller and asserts the
//! count is zero at every block-I/O wait point.
//!
//! Implements RFC 0004 — Workstream C normative invariant:
//! **"no spin lock is held across a block-I/O wait."** Holding a
//! spinlock across a device wait can deadlock: the wait may schedule
//! away (or, even on a polled driver, take milliseconds), during
//! which any task that needs the same lock spins burning CPU and any
//! IRQ handler that touches the lock dead-spins on a CPU that has
//! it disabled.
//!
//! # Mechanism
//!
//! - [`SpinLock::lock`] / [`SpinLockGuard::drop`] increment /
//!   decrement [`HELD_SPINLOCKS`] under `cfg(debug_assertions)`. In
//!   release builds both calls are no-ops and the wrapper compiles
//!   to the same code as the underlying `spin::Mutex`.
//! - The kernel's [`crate::sync::IrqLock`] participates in the same
//!   counter so a held IRQ-masking spinlock is visible to the
//!   tripwire too.
//! - [`assert_no_spinlocks_held`] panics with a message that names
//!   the I/O site (caller) and the held-lock count if the invariant
//!   is violated. Callers pass a short label like
//!   `"BlockCache::bread → device.read_at"` so the panic carries
//!   triage context out of the box.
//!
//! # Per-CPU
//!
//! vibix is single-CPU today; the counter is a single
//! [`AtomicU32`] standing in for the future per-CPU slot. When SMP
//! lands, this becomes a `[AtomicU32; NCPU]` indexed by `cpu::id()`;
//! every public entrypoint here is the natural seam to widen.
//!
//! # Cost in release builds
//!
//! Every counter mutation is `#[cfg(debug_assertions)]`-gated; the
//! `#[inline]` no-op stubs let the optimiser delete the call entirely.
//! [`SpinLock<T>`] is `#[repr(transparent)]` over `spin::Mutex<T>` so
//! the wrapper has no runtime cost beyond what the optimiser already
//! folds away.

#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicU32, Ordering};

/// Per-CPU count of spinlocks currently held by this CPU. Single-CPU
/// today; widen to `[AtomicU32; NCPU]` indexed by `cpu::id()` when SMP
/// arrives.
///
/// Only present in debug builds — release builds compile out the
/// counter entirely.
#[cfg(debug_assertions)]
static HELD_SPINLOCKS: AtomicU32 = AtomicU32::new(0);

/// Bump the held-spinlock counter. Called by [`SpinLock::lock`] and
/// the kernel's `IrqLock::lock` immediately after the underlying
/// spin acquire returns.
///
/// In release builds this is a no-op the optimiser deletes.
#[cfg(debug_assertions)]
#[inline]
pub fn inc_held_spinlocks() {
    HELD_SPINLOCKS.fetch_add(1, Ordering::Relaxed);
}

/// Release-build no-op. See the debug-build sibling above.
#[cfg(not(debug_assertions))]
#[inline]
pub fn inc_held_spinlocks() {}

/// Decrement the held-spinlock counter. Called by the spinlock
/// guard's `Drop` impl just before releasing the underlying spin
/// lock.
#[cfg(debug_assertions)]
#[inline]
pub fn dec_held_spinlocks() {
    // `saturating_sub` semantics via fetch_sub then clamp would
    // burn an extra atomic op; instead, debug-assert the underflow
    // would never happen (an unbalanced dec means a guard was
    // dropped without a paired inc, which is a wrapper bug).
    let prev = HELD_SPINLOCKS.fetch_sub(1, Ordering::Relaxed);
    debug_assert!(
        prev > 0,
        "debug_lockdep: dec_held_spinlocks underflow — guard dropped without paired inc"
    );
}

/// Release-build no-op. See the debug-build sibling above.
#[cfg(not(debug_assertions))]
#[inline]
pub fn dec_held_spinlocks() {}

/// Read the current held-spinlock count. Exposed for tests; production
/// callers should prefer [`assert_no_spinlocks_held`].
#[cfg(debug_assertions)]
#[inline]
pub fn held_spinlocks() -> u32 {
    HELD_SPINLOCKS.load(Ordering::Relaxed)
}

/// Release-build stub: always reports zero (no tracking).
#[cfg(not(debug_assertions))]
#[inline]
pub fn held_spinlocks() -> u32 {
    0
}

/// Panic if any spinlock is currently held. Called immediately
/// before every block-I/O wait point in `kernel/src/block/`.
///
/// `io_site` should name the caller, e.g.
/// `"BlockCache::bread → device.read_at"`. The panic message
/// includes both the site and the held-count so a triage reader
/// sees what site tripped and how many locks were stuck.
///
/// In release builds this compiles to a no-op and the `io_site`
/// string is dead code (the optimiser deletes the call).
#[cfg(debug_assertions)]
#[inline]
#[track_caller]
pub fn assert_no_spinlocks_held(io_site: &str) {
    let n = held_spinlocks();
    assert!(
        n == 0,
        "debug_lockdep: invariant violated at {} — {} spinlock(s) held across block-I/O wait. \
         RFC 0004 §Buffer cache: no spin lock may be held across a block-I/O wait. \
         Drop the held SpinLock / IrqLock guard before issuing the I/O.",
        io_site,
        n,
    );
}

/// Release-build no-op. The argument is `_` so the call site
/// optimises out cleanly.
#[cfg(not(debug_assertions))]
#[inline]
pub fn assert_no_spinlocks_held(_io_site: &str) {}

// ------------------------------------------------------------------
// SpinLock<T> — instrumented wrapper around spin::Mutex<T>.
// ------------------------------------------------------------------

#[cfg(any(test, target_os = "none"))]
mod spinlock {
    use super::{dec_held_spinlocks, inc_held_spinlocks};
    use core::ops::{Deref, DerefMut};

    /// Tracking wrapper around `spin::Mutex<T>` — bumps the
    /// per-CPU held-spinlock counter on `lock`, decrements on
    /// guard drop. Use anywhere a plain `spin::Mutex` would do
    /// when the lock is reachable from a path that may eventually
    /// hit a block-I/O wait — the wrapper makes a violation
    /// trip [`super::assert_no_spinlocks_held`] at the wait
    /// point.
    ///
    /// `#[repr(transparent)]` so a `SpinLock<T>` and a
    /// `spin::Mutex<T>` have identical memory layouts; the
    /// wrapper's only runtime cost is the debug-build counter
    /// op (compiled out of release).
    #[repr(transparent)]
    pub struct SpinLock<T: ?Sized> {
        inner: spin::Mutex<T>,
    }

    impl<T> SpinLock<T> {
        /// Construct a new `SpinLock` wrapping `value`. `const`
        /// so the wrapper can live in a `static`.
        pub const fn new(value: T) -> Self {
            Self {
                inner: spin::Mutex::new(value),
            }
        }

        /// Consume the lock and return the inner value. Bypasses
        /// the counter — no acquire happens.
        pub fn into_inner(self) -> T {
            self.inner.into_inner()
        }
    }

    impl<T: ?Sized> SpinLock<T> {
        /// Acquire the lock. Spins on contention; bumps the
        /// held-spinlock counter on success.
        pub fn lock(&self) -> SpinLockGuard<'_, T> {
            let guard = self.inner.lock();
            inc_held_spinlocks();
            SpinLockGuard { guard: Some(guard) }
        }

        /// Try to acquire without spinning. On `Some`, bumps the
        /// counter; on `None` the counter is untouched.
        pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
            let guard = self.inner.try_lock()?;
            inc_held_spinlocks();
            Some(SpinLockGuard { guard: Some(guard) })
        }

        /// Whether the lock is currently held. Advisory only —
        /// the state may change immediately after the check.
        pub fn is_locked(&self) -> bool {
            self.inner.is_locked()
        }
    }

    /// RAII guard for a [`SpinLock`]. Decrements the held-spinlock
    /// counter and releases the underlying `spin::Mutex` on drop.
    pub struct SpinLockGuard<'a, T: ?Sized + 'a> {
        // `Option` so `Drop` can take the inner guard and drop it
        // *after* decrementing the counter — the counter must
        // observe the unlock before any subsequent
        // `assert_no_spinlocks_held` runs on this CPU.
        guard: Option<spin::MutexGuard<'a, T>>,
    }

    impl<T: ?Sized> Deref for SpinLockGuard<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.guard.as_ref().expect("guard present until drop")
        }
    }

    impl<T: ?Sized> DerefMut for SpinLockGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            self.guard.as_mut().expect("guard present until drop")
        }
    }

    impl<T: ?Sized> Drop for SpinLockGuard<'_, T> {
        fn drop(&mut self) {
            // Decrement first so the counter is in sync with the
            // "no longer holding any lock" state by the time the
            // underlying spin lock is released. Order doesn't
            // strictly matter on a single CPU (no preemption
            // window between the two ops on the same core), but
            // dec-before-release matches the conventional
            // release-acquire pattern of "publish state, then
            // open the gate".
            dec_held_spinlocks();
            self.guard = None;
        }
    }
}

#[cfg(any(test, target_os = "none"))]
pub use spinlock::{SpinLock, SpinLockGuard};

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    /// Serialise tests that touch the shared `HELD_SPINLOCKS` static.
    /// libtest runs `#[test]`s in parallel by default (one per worker
    /// thread); without this lock two tests would interleave their
    /// `lock` / `drop` / `assert_no_spinlocks_held` calls on the
    /// shared counter and one would observe the other's intermediate
    /// state. Same pattern as `kernel/src/fs/vfs/gc_queue.rs`. Use
    /// `std::sync::Mutex` so a panicking test poisons the lock
    /// rather than deadlocking the suite — `into_inner` recovers.
    #[cfg(debug_assertions)]
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the test lock and reset the counter. Returned guard
    /// holds the `TEST_LOCK` for the lifetime of the test scope —
    /// keep it alive (e.g. `let _guard = test_guard();`) so other
    /// tests block until this one finishes.
    #[cfg(debug_assertions)]
    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Reset under the lock so a previous test that paniced
        // mid-acquire (leaving the counter > 0) doesn't poison
        // the next test's invariant.
        HELD_SPINLOCKS.store(0, Ordering::Relaxed);
        g
    }

    #[cfg(debug_assertions)]
    #[test]
    fn counter_increments_on_lock_decrements_on_drop() {
        let _t = test_guard();
        let m = SpinLock::new(0u32);
        assert_eq!(held_spinlocks(), 0);
        {
            let _g = m.lock();
            assert_eq!(held_spinlocks(), 1);
        }
        assert_eq!(held_spinlocks(), 0);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn counter_tracks_nested_locks() {
        let _t = test_guard();
        let a = SpinLock::new(1u8);
        let b = SpinLock::new(2u8);
        let _ga = a.lock();
        let _gb = b.lock();
        assert_eq!(held_spinlocks(), 2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn try_lock_increments_only_on_success() {
        let _t = test_guard();
        let m = SpinLock::new(7u8);
        let _g = m.lock();
        assert_eq!(held_spinlocks(), 1);
        // Contended try_lock must NOT bump the counter — it didn't
        // acquire the lock.
        assert!(m.try_lock().is_none());
        assert_eq!(held_spinlocks(), 1);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn assert_passes_with_no_locks_held() {
        let _t = test_guard();
        // Should not panic.
        assert_no_spinlocks_held("test:no-lock-site");
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "debug_lockdep: invariant violated at test:violation-site")]
    fn assert_panics_when_lock_held() {
        // `should_panic` test still needs the lock to keep the
        // counter free of interference from a sibling test until
        // the panic fires. The `Mutex` poisoning recovers in
        // `test_guard`'s `unwrap_or_else`.
        let _t = test_guard();
        let m = SpinLock::new(0u8);
        let _g = m.lock();
        // Holding `_g` across this call MUST panic.
        assert_no_spinlocks_held("test:violation-site");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn guard_deref_and_mutate() {
        let _t = test_guard();
        let m = SpinLock::new(0u32);
        {
            let mut g = m.lock();
            *g = 42;
        }
        assert_eq!(*m.lock(), 42);
    }

    /// Release-build sanity: with `debug_assertions` off the
    /// counter is gone and the assertion is a no-op. We can only
    /// observe this indirectly — the inc/dec/held APIs all return
    /// or do nothing, so a held lock should NOT trip the assert.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_assert_is_noop_even_with_held_lock() {
        let m = SpinLock::new(0u8);
        let _g = m.lock();
        // No panic — release builds skip tracking entirely.
        assert_no_spinlocks_held("test:release-noop");
        assert_eq!(held_spinlocks(), 0);
    }
}
