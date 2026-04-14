//! Blocking synchronisation primitives: sleeping mutex, waitqueue,
//! bounded SPSC channel.
//!
//! These sit on top of the round-robin scheduler in [`crate::task`]:
//! they park the calling task with
//! [`task::block_current`](crate::task::block_current) when they'd
//! otherwise need to busy-wait, and wake it with
//! [`task::wake`](crate::task::wake) once progress is possible.
//!
//! ## When to pick each one
//!
//! - [`BlockingMutex`] — mutual exclusion that doesn't burn CPU under
//!   contention. Interface mirrors `spin::Mutex`; drop-in for any
//!   critical section that might be held across a scheduling point.
//! - [`BlockingRwLock`] — multi-reader / single-writer sleeping lock.
//!   Use when readers dominate and a short-lived writer can't afford
//!   to spin. Writers get priority over newly-arriving readers, so
//!   they aren't starved under reader churn.
//! - [`Semaphore`] — counting semaphore with `acquire` / `release`.
//!   Reach for this when the resource is a budget rather than a
//!   single critical section (e.g. VFS `ChildState::Loading`
//!   deduplicating a first-lookup-of-a-name).
//! - [`WaitQueue`] — primitive building block. Tasks call
//!   [`WaitQueue::wait_while`] with a condition; wakers call
//!   [`WaitQueue::notify_one`] / [`notify_all`] after changing state
//!   the condition depends on. Both of the other primitives are built
//!   on this.
//! - [`spsc`] — single-producer / single-consumer bounded channel.
//!   The simplest message-passing shape; reach for this when each
//!   side has exactly one endpoint.
//! - [`mpmc`] — multi-producer / multi-consumer bounded channel.
//!   Same shape as `spsc` but both endpoints are `Clone`; pay the
//!   extra endpoint-count bookkeeping when you need fan-in or
//!   fan-out.
//!
//! Both channel variants observe the close / hang-up protocol:
//! dropping the last sender wakes parked receivers (which drain,
//! then see `None`); dropping the last receiver wakes parked
//! senders (which see `Err(val)`).
//!
//! ## Task-context only
//!
//! Every `notify` / `wake` path here acquires the scheduler lock. The
//! preempt-tick ISR uses `try_lock` on the same lock and bails on
//! contention, which is safe; an ISR that calls `notify_one` directly,
//! however, would deadlock if it interrupted a task already holding
//! that lock. If an IRQ needs to wake a task, post to a lock-free
//! queue (see `crate::input`'s keyboard ring) and let a kernel task
//! drain it and call `notify_one` from task context.
//!
//! ## Lock order
//!
//! The primitives here establish a strict acquisition order so that
//! no cycle can form:
//!
//! ```text
//!   WaitQueue.inner ── ▶ (data lock, e.g. BlockingMutex.state,
//!                          spsc::Shared.buf)
//!   WaitQueue.inner ── ▶ SCHED  (via task::block_current /
//!                                 task::current_id)
//! ```
//!
//! Nothing acquires `WaitQueue.inner` while already holding a data
//! lock or `SCHED`, so the graph is a DAG.

pub mod mpmc;
pub mod mutex;
pub mod rwlock;
pub mod semaphore;
pub mod spsc;
pub mod waitqueue;

pub use mutex::{BlockingMutex, MutexGuard};
pub use rwlock::{BlockingRwLock, RwLockReadGuard, RwLockWriteGuard};
pub use semaphore::Semaphore;
pub use waitqueue::WaitQueue;
