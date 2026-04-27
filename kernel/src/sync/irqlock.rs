//! IRQ-masking spinlock.
//!
//! An [`IrqLock<T>`] is a thin wrapper around `spin::Mutex<T>` that
//! disables local interrupts for the duration the guard is held. It's
//! the primitive for data shared between task context and an ISR:
//!
//! - Task-context acquire: reads the current `RFLAGS.IF`, clears it,
//!   takes the spin lock.
//! - ISR-context acquire: IF is already clear (interrupt gates), so
//!   the save/restore is a no-op — the lock is simply acquired.
//! - Guard drop: releases the spin lock, *then* restores the saved
//!   IF. Release-before-sti is deliberate — if we sti'd while still
//!   holding the lock, a pending IRQ could observe the ISR's view of
//!   the data mid-update.
//!
//! This mirrors Linux's `spin_lock_irqsave` semantics. Prefer
//! [`IrqLock`] over pairing `spin::Mutex` with hand-rolled
//! `interrupts::disable()` / `interrupts::enable()` bookends — the
//! automatic drop makes it impossible to forget the restore, and
//! `are_enabled()` + `disable()` on acquire correctly nests when
//! IRQs are already disabled.
//!
//! # When *not* to use
//!
//! - If the lock is held across a scheduling point (`block_current`,
//!   `yield`, or any blocking-primitive acquire), use
//!   [`super::BlockingMutex`] instead. Parking with IF disabled would
//!   hang the kernel.
//! - If the data is only ever touched from task context, a plain
//!   `spin::Mutex` is cheaper — no IF read/write on every acquire —
//!   and the module comment for the lock should state that invariant
//!   so future code doesn't paper an ISR path onto it.

use core::ops::{Deref, DerefMut};

/// Wrapper around `spin::Mutex<T>` that disables interrupts while held.
///
/// Interface mirrors `spin::Mutex` — `lock`, `try_lock`, `is_locked`.
/// The returned [`IrqLockGuard`] derefs to `T` and releases the lock
/// and restores the prior interrupt-flag state on drop.
pub struct IrqLock<T: ?Sized> {
    inner: spin::Mutex<T>,
}

/// RAII guard for an [`IrqLock`]. Releases the inner spin lock then
/// restores the interrupt-flag to the value it held before `lock()`
/// was called.
pub struct IrqLockGuard<'a, T: ?Sized + 'a> {
    // `Option` so `Drop` can take the inner guard and drop it *before*
    // restoring IF — the order matters (see module docs).
    guard: Option<spin::MutexGuard<'a, T>>,
    prev_if: bool,
}

impl<T> IrqLock<T> {
    /// Create a new [`IrqLock`] wrapping `value`.
    pub const fn new(value: T) -> Self {
        Self {
            inner: spin::Mutex::new(value),
        }
    }
}

impl<T: ?Sized> IrqLock<T> {
    /// Disable interrupts (saving the prior state), then acquire the
    /// spin lock. The returned guard keeps IRQs masked until dropped.
    pub fn lock(&self) -> IrqLockGuard<'_, T> {
        let prev_if = arch_if::save_and_disable();
        let guard = self.inner.lock();
        // Count the IRQ-masking spinlock toward the held-spinlock
        // invariant (RFC 0004 §Buffer cache, no-spin-across-I/O).
        // A held `IrqLock` is the *worst* lock to hold across a
        // block-I/O wait — it disables IRQs, so the wait can't
        // even progress on tick.
        crate::debug_lockdep::inc_held_spinlocks();
        IrqLockGuard {
            guard: Some(guard),
            prev_if,
        }
    }

    /// Try to acquire the lock without blocking. Returns `None` if
    /// already held by someone else; on success, behaves like
    /// [`lock`](Self::lock).
    pub fn try_lock(&self) -> Option<IrqLockGuard<'_, T>> {
        let prev_if = arch_if::save_and_disable();
        match self.inner.try_lock() {
            Some(guard) => {
                crate::debug_lockdep::inc_held_spinlocks();
                Some(IrqLockGuard {
                    guard: Some(guard),
                    prev_if,
                })
            }
            None => {
                arch_if::restore(prev_if);
                None
            }
        }
    }

    /// Whether the lock is currently held. Advisory only — the state
    /// may change immediately after the check.
    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }
}

impl<T: ?Sized> Deref for IrqLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().expect("guard present until drop")
    }
}

impl<T: ?Sized> DerefMut for IrqLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().expect("guard present until drop")
    }
}

impl<T: ?Sized> Drop for IrqLockGuard<'_, T> {
    fn drop(&mut self) {
        // Release the spin lock first. Restoring IF before drop would
        // let a pending IRQ observe the data under the (still held)
        // lock semantics and deadlock-via-reentry.
        self.guard = None;
        // Decrement after the underlying spin release so the
        // counter reflects "no longer holding the lock" by the
        // time IF is restored and any IRQ that fires can run an
        // `assert_no_spinlocks_held`.
        crate::debug_lockdep::dec_held_spinlocks();
        arch_if::restore(self.prev_if);
    }
}

/// Thin abstraction over the interrupt-flag save/restore primitives so
/// host `#[cfg(test)]` builds can stub them with an [`AtomicBool`].
#[cfg(target_os = "none")]
mod arch_if {
    use x86_64::instructions::interrupts;

    #[inline(always)]
    pub(super) fn save_and_disable() -> bool {
        let prev = interrupts::are_enabled();
        interrupts::disable();
        prev
    }

    #[inline(always)]
    pub(super) fn restore(prev: bool) {
        if prev {
            interrupts::enable();
        }
    }
}

#[cfg(not(target_os = "none"))]
mod arch_if {
    use core::sync::atomic::{AtomicBool, Ordering};

    // Host stub: a single process-wide "interrupts enabled" flag used
    // by unit tests to validate save/restore ordering. Real kernels
    // use the CPU flag.
    static IF_STATE: AtomicBool = AtomicBool::new(true);

    pub(super) fn save_and_disable() -> bool {
        IF_STATE.swap(false, Ordering::SeqCst)
    }

    pub(super) fn restore(prev: bool) {
        IF_STATE.store(prev, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(super) fn test_is_enabled() -> bool {
        IF_STATE.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(super) fn test_set(enabled: bool) {
        IF_STATE.store(enabled, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_unlock_value_round_trip() {
        arch_if::test_set(true);
        let m = IrqLock::new(42u32);
        {
            let mut g = m.lock();
            assert_eq!(*g, 42);
            *g = 99;
        }
        assert_eq!(*m.lock(), 99);
    }

    #[test]
    fn try_lock_fails_while_held() {
        arch_if::test_set(true);
        let m = IrqLock::new(0u8);
        let g = m.lock();
        assert!(m.try_lock().is_none());
        drop(g);
        assert!(m.try_lock().is_some());
    }

    #[test]
    fn guard_masks_ifs_during_critical_section() {
        arch_if::test_set(true);
        let m = IrqLock::new(());
        {
            let _g = m.lock();
            assert!(!arch_if::test_is_enabled(), "IF must be disabled in guard");
        }
        assert!(arch_if::test_is_enabled(), "IF must be restored on drop");
    }

    #[test]
    fn guard_restores_prior_if_state_when_already_disabled() {
        arch_if::test_set(false);
        let m = IrqLock::new(());
        {
            let _g = m.lock();
            assert!(!arch_if::test_is_enabled());
        }
        // Prior IF was disabled — drop must NOT enable it.
        assert!(
            !arch_if::test_is_enabled(),
            "IF must stay disabled when prior state was disabled"
        );
    }

    #[test]
    fn try_lock_failure_restores_if_state() {
        arch_if::test_set(true);
        let m = IrqLock::new(());
        let _held = m.lock();
        // Before calling try_lock, IF is false (held by _held). The
        // contention path must not leave IF clobbered — specifically,
        // it must not leave the nested save stuck at `false`.
        let attempt = m.try_lock();
        assert!(attempt.is_none());
        // _held still in scope, so IF still false (correct).
        assert!(!arch_if::test_is_enabled());
        drop(_held);
        assert!(arch_if::test_is_enabled());
    }
}
