//! `BlockingRwLock<T>` — multi-reader / single-writer lock that parks
//! on contention instead of spinning.
//!
//! Shares the park/wake path with [`BlockingMutex`] via a single
//! [`WaitQueue`]: both readers and writers enqueue on the same queue,
//! so the wake order is FIFO — a writer blocked behind a reader wakes
//! before a later reader does, which keeps writers making progress
//! under reader churn.
//!
//! Lock order (see [`super`] module docs): `WaitQueue.inner` → the
//! internal `state` spin-lock.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use spin::Mutex as SpinMutex;

use super::WaitQueue;

/// Internal lock state. `writer` is exclusive with any non-zero
/// `readers` count. `writer_waiting` tells arriving readers to queue
/// behind a parked writer so long reader streams can't indefinitely
/// defer a writer's acquisition.
#[derive(Clone, Copy)]
struct State {
    readers: u32,
    writer: bool,
    writer_waiting: u32,
}

impl State {
    const fn new() -> Self {
        Self {
            readers: 0,
            writer: false,
            writer_waiting: 0,
        }
    }

    fn can_read(&self) -> bool {
        !self.writer && self.writer_waiting == 0
    }

    fn can_write(&self) -> bool {
        !self.writer && self.readers == 0
    }
}

/// Multi-reader / single-writer sleeping lock.
pub struct BlockingRwLock<T: ?Sized> {
    /// Short-lived spin-protected state. Nobody holds this across a
    /// scheduling point.
    state: SpinMutex<State>,
    /// Shared FIFO parking queue for both readers and writers.
    waiters: WaitQueue,
    /// Protected data. Access is serialised by the read/write protocol.
    data: UnsafeCell<T>,
}

// `data` access is serialised by the rwlock protocol: `&T` is handed
// out via the read guard (needs `T: Sync` to share across tasks) and
// `&mut T` via the write guard (needs `T: Send` to transfer ownership
// of mutation across tasks).
unsafe impl<T: ?Sized + Send> Send for BlockingRwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for BlockingRwLock<T> {}

impl<T> BlockingRwLock<T> {
    /// Construct a new rwlock. `const` so the lock can live in a
    /// `static`.
    pub const fn new(val: T) -> Self {
        Self {
            state: SpinMutex::new(State::new()),
            waiters: WaitQueue::new(),
            data: UnsafeCell::new(val),
        }
    }

    /// Consume the lock and return the protected value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> BlockingRwLock<T> {
    /// Number of tasks currently parked on this rwlock (readers or
    /// writers waiting). Intended for test-harness synchronisation — a
    /// driver can spin on `waiter_count() >= N` to confirm N workers
    /// have actually enqueued before firing a release. Not appropriate
    /// for production logic; the count can change the instant it's read.
    pub fn waiter_count(&self) -> usize {
        self.waiters.waiter_count()
    }

    /// Try to acquire a shared (read) lock without parking.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let mut st = self.state.lock();
        if st.can_read() {
            st.readers += 1;
            Some(RwLockReadGuard { rw: self })
        } else {
            None
        }
    }

    /// Try to acquire the exclusive (write) lock without parking.
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        let mut st = self.state.lock();
        if st.can_write() {
            st.writer = true;
            Some(RwLockWriteGuard { rw: self })
        } else {
            None
        }
    }

    /// Acquire a shared (read) lock, parking until one is available.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            {
                let mut st = self.state.lock();
                if st.can_read() {
                    st.readers += 1;
                    return RwLockReadGuard { rw: self };
                }
            }
            // Park. `wait_while` re-checks the cond under the
            // waitqueue lock, so a release between our fast-path
            // check and the park can't be dropped — see
            // `BlockingMutex::lock`.
            self.waiters.wait_while(|| !self.state.lock().can_read());
        }
    }

    /// Acquire the exclusive (write) lock, parking until it's
    /// available. New readers queue behind a parked writer, so long
    /// reader streams don't indefinitely defer writer acquisition.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        // Fast path: uncontended grab. No need to touch
        // `writer_waiting` if the lock is immediately available.
        {
            let mut st = self.state.lock();
            if st.can_write() {
                st.writer = true;
                return RwLockWriteGuard { rw: self };
            }
            // Contended — register ourselves so readers back off.
            st.writer_waiting += 1;
        }
        loop {
            {
                let mut st = self.state.lock();
                if st.can_write() {
                    st.writer = true;
                    st.writer_waiting -= 1;
                    return RwLockWriteGuard { rw: self };
                }
            }
            self.waiters.wait_while(|| !self.state.lock().can_write());
        }
    }
}

/// RAII shared-access guard. Drop to release; wakes waiters if the
/// last reader leaves the lock in a state a writer could claim.
pub struct RwLockReadGuard<'a, T: ?Sized> {
    rw: &'a BlockingRwLock<T>,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: at least one reader is live, so no writer can hold
        // the lock — shared `&T` is sound.
        unsafe { &*self.rw.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        let was_last = {
            let mut st = self.rw.state.lock();
            st.readers -= 1;
            st.readers == 0
        };
        if was_last {
            // Last reader out: wake every waiter so the FIFO head —
            // likely the writer that incremented `writer_waiting` —
            // can take the lock. Anyone who doesn't get it re-parks.
            self.rw.waiters.notify_all();
        }
    }
}

/// RAII exclusive-access guard. Drop to release; wakes every waiter
/// so whoever's at the head of the FIFO queue can proceed.
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    rw: &'a BlockingRwLock<T>,
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: writer flag is set, so no readers are live.
        unsafe { &*self.rw.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: exclusive writer flag implies no other guards.
        unsafe { &mut *self.rw.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        {
            let mut st = self.rw.state.lock();
            st.writer = false;
        }
        // Wake every waiter so a burst of readers queued behind us
        // can all re-check and enter, or the next writer can claim.
        self.rw.waiters.notify_all();
    }
}
