//! `Semaphore` — counting semaphore that parks on exhaustion.
//!
//! Introduced by RFC 0002 for `ChildState::Loading` in the VFS
//! dentry cache, where it serializes the first lookup-of-a-name.
//! General-purpose: a semaphore with N permits lets up to N acquirers
//! through concurrently; further acquirers park until a permit is
//! released.
//!
//! Non-reentrant, matching the rest of `kernel/src/sync/`. Shares the
//! park/wake path with [`BlockingMutex`] via a [`WaitQueue`].
//!
//! Lock order (see [`super`] module docs): `WaitQueue.inner` → the
//! internal `permits` spin-lock.

use spin::Mutex as SpinMutex;

use super::WaitQueue;

/// Counting semaphore.
pub struct Semaphore {
    /// Available permits. Short-lived spin lock.
    permits: SpinMutex<usize>,
    /// FIFO waiters parked on `acquire`.
    waiters: WaitQueue,
}

impl Semaphore {
    /// Construct a semaphore with `permits` initial permits. `const`
    /// so the semaphore can live in a `static`.
    pub const fn new(permits: usize) -> Self {
        Self {
            permits: SpinMutex::new(permits),
            waiters: WaitQueue::new(),
        }
    }

    /// Try to take one permit without parking. Returns `true` if a
    /// permit was taken.
    pub fn try_acquire(&self) -> bool {
        let mut p = self.permits.lock();
        if *p > 0 {
            *p -= 1;
            true
        } else {
            false
        }
    }

    /// Take one permit, parking if none are available.
    pub fn acquire(&self) {
        loop {
            {
                let mut p = self.permits.lock();
                if *p > 0 {
                    *p -= 1;
                    return;
                }
            }
            // Park. The `cond` re-checks under the waitqueue lock, so
            // a release between our fast-path check and the park
            // can't be lost — see `BlockingMutex::lock`.
            self.waiters.wait_while(|| *self.permits.lock() == 0);
        }
    }

    /// Release one permit. Wakes one parked acquirer, if any.
    pub fn release(&self) {
        {
            let mut p = self.permits.lock();
            // Saturating so a buggy over-release doesn't silently
            // wrap to a huge permit count. Debug builds trip the
            // assert first for visibility.
            debug_assert!(
                *p < usize::MAX,
                "Semaphore::release overflowed permit count"
            );
            *p = p.saturating_add(1);
        }
        self.waiters.notify_one();
    }

    /// Number of permits currently available. Intended for tests;
    /// racy by nature (the count can change the instant it's read).
    pub fn available(&self) -> usize {
        *self.permits.lock()
    }
}
