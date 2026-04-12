//! `BlockingMutex<T>` — mutual exclusion that parks on contention
//! instead of spinning.
//!
//! Interface mirrors `spin::Mutex`: [`lock`] returns a RAII guard that
//! derefs to `&mut T` and releases the lock on drop. A contended
//! `lock` call parks the task via [`WaitQueue::wait_while`] until the
//! current holder releases.
//!
//! Lock order (see [`super`] module docs): `WaitQueue.inner` → the
//! internal `state` spin-lock. Nothing outside this module takes those
//! two locks in reverse order, so no deadlock cycle can form.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use spin::Mutex as SpinMutex;

use super::WaitQueue;

/// Sleeping mutex.
pub struct BlockingMutex<T: ?Sized> {
    /// `true` while the mutex is held. Guarded by a short-lived
    /// spinlock that nobody holds across a scheduling point.
    state: SpinMutex<bool>,
    /// Parked tasks waiting for the mutex to be released.
    waiters: WaitQueue,
    /// The protected data. `UnsafeCell` because we hand out `&mut`
    /// through the guard; access is serialised by `state == true`.
    data: UnsafeCell<T>,
}

// Access to `data` is serialised by the mutex protocol — safe to share
// the mutex itself across tasks whenever `T` is `Send`.
unsafe impl<T: ?Sized + Send> Send for BlockingMutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for BlockingMutex<T> {}

impl<T> BlockingMutex<T> {
    /// Construct a new mutex protecting `val`. `const` so the mutex
    /// can live in a `static`.
    pub const fn new(val: T) -> Self {
        Self {
            state: SpinMutex::new(false),
            waiters: WaitQueue::new(),
            data: UnsafeCell::new(val),
        }
    }

    /// Consume the mutex and return the protected value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> BlockingMutex<T> {
    /// Try to acquire without parking. Returns `None` if the mutex is
    /// currently held by someone else.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let mut held = self.state.lock();
        if *held {
            None
        } else {
            *held = true;
            Some(MutexGuard { mu: self })
        }
    }

    /// Acquire the mutex, parking the current task if it's contended.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            // Fast path — uncontended grab.
            {
                let mut held = self.state.lock();
                if !*held {
                    *held = true;
                    return MutexGuard { mu: self };
                }
            }
            // Slow path — park until the lock looks available. The
            // `cond` runs under the waitqueue lock, which is the lock
            // point that makes the park race-free: if the holder
            // releases between our fast-path check and the
            // `wait_while` cond, the cond sees `*state == false` and
            // returns without parking. If it releases between cond
            // and `block_current`, `notify_one` pops us and
            // `task::wake` sets `wake_pending` — `block_current`
            // consumes it and returns.
            self.waiters.wait_while(|| *self.state.lock());
        }
    }
}

/// RAII guard. Drop to release the mutex; wakes one waiter.
pub struct MutexGuard<'a, T: ?Sized> {
    mu: &'a BlockingMutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the mutex is held (see `state == true`), so we have
        // exclusive access to `data`.
        unsafe { &*self.mu.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above — exclusive access implied by a live guard.
        unsafe { &mut *self.mu.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // Publish the release BEFORE notifying, so a woken waiter's
        // cond re-check sees `*state == false`.
        *self.mu.state.lock() = false;
        self.mu.waiters.notify_one();
    }
}
