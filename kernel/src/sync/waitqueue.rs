//! Waitqueue: the one primitive on which [`super::BlockingMutex`] and
//! [`super::spsc`] are built.
//!
//! A waitqueue stores the ids of tasks that have declared interest in
//! a condition. [`WaitQueue::wait_while`] is the standard park loop;
//! [`WaitQueue::notify_one`] and [`WaitQueue::notify_all`] are the
//! wake side.
//!
//! ## Lost-wakeup protocol
//!
//! The tricky case is:
//!
//! 1. Waiter checks the condition, sees "must block", adds itself to
//!    the queue, drops the queue lock.
//! 2. Before the waiter reaches [`task::block_current`], the waker
//!    runs, flips the state the condition tests, and calls
//!    [`WaitQueue::notify_one`]. `notify_one` pops the waiter and
//!    calls [`task::wake`], which finds the waiter still Running and
//!    sets its `wake_pending` flag.
//! 3. Waiter finally calls [`task::block_current`], which consumes
//!    `wake_pending` and returns immediately.
//! 4. Loop re-checks the condition, sees it's satisfied, returns.
//!
//! The invariant is: *between enqueuing self and calling
//! `block_current`, a wake cannot be dropped on the floor.* The
//! `wake_pending` flag on the task carries the signal across the
//! window where the waiter is enqueued but not yet parked.

use alloc::collections::VecDeque;
use spin::Mutex;

use crate::task;

/// Blocking wait queue.
///
/// See the module docs for the lost-wakeup protocol and lock order.
pub struct WaitQueue {
    inner: Mutex<VecDeque<usize>>,
}

impl WaitQueue {
    /// Create an empty wait queue. `const` so the primitive can live
    /// in a `static`.
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
        }
    }

    /// Block the current task while `cond` is true.
    ///
    /// Classic "predicate loop" wait: on entry `cond` is checked under
    /// the queue lock; if true, the current task enqueues itself,
    /// drops the lock, and parks. On wake it re-checks `cond` and
    /// returns once the predicate is false.
    ///
    /// `cond` is called repeatedly — make it pure and side-effect
    /// free. It may itself take other locks (e.g. a data mutex) as
    /// long as those locks are ordered *after* `WaitQueue.inner` in
    /// the module's lock graph.
    pub fn wait_while<F: FnMut() -> bool>(&self, mut cond: F) {
        let tid = task::current_id();

        loop {
            // Enqueue first, then check. The ordering is what makes
            // the wake-before-park race safe: if a wake fires after
            // the push but before `block_current`, it'll either pop
            // us from the queue (and set `wake_pending` via
            // `task::wake`) or miss us, but in both cases the
            // condition will also have changed, and the final
            // `cond()` check below catches it.
            {
                let mut q = self.inner.lock();
                if !cond() {
                    return;
                }
                q.push_back(tid);
            }

            task::block_current();

            // Woken (or wake was already pending). Remove any stale
            // self-entry in case we came out via `wake_pending` rather
            // than a `notify_one` pop. Cheap linear scan — queue is
            // bounded by the number of concurrent waiters.
            {
                let mut q = self.inner.lock();
                q.retain(|&id| id != tid);
            }
            // Fall through to loop — re-check cond.
        }
    }

    /// Wake exactly one waiter, if any.
    ///
    /// Call *after* publishing the state change that would make a
    /// waiter's `cond()` return false. Order matters: if you notify
    /// before publishing, the waiter may observe the old state on its
    /// re-check and park again.
    pub fn notify_one(&self) {
        let tid = { self.inner.lock().pop_front() };
        if let Some(tid) = tid {
            task::wake(tid);
        }
    }

    /// Number of tasks currently enqueued on this waitqueue.
    ///
    /// Intended for test-harness synchronisation: a driver can spin on
    /// `waiter_count() >= N` to confirm that N workers have actually
    /// parked before firing a wake, closing the gap between a worker's
    /// pre-call readiness signal and its real enqueue inside
    /// `wait_while`. Not appropriate for production logic — the count
    /// can change the instant it's returned.
    pub fn waiter_count(&self) -> usize {
        self.inner.lock().len()
    }

    /// Wake every currently-registered waiter.
    pub fn notify_all(&self) {
        loop {
            let tid = { self.inner.lock().pop_front() };
            match tid {
                Some(tid) => task::wake(tid),
                None => return,
            }
        }
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}
