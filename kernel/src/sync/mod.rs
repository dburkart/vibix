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
//! - [`WaitQueue`] — primitive building block. Tasks call
//!   [`WaitQueue::wait_while`] with a condition; wakers call
//!   [`WaitQueue::notify_one`] / [`notify_all`] after changing state
//!   the condition depends on. Both of the other primitives are built
//!   on this.
//! - [`spsc`] — single-producer / single-consumer bounded channel.
//!   The simplest message-passing shape; MPSC/MPMC variants can be
//!   added as follow-ups once the SPSC case has baked in-tree.
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

pub mod mutex;
pub mod spsc;
pub mod waitqueue;

pub use mutex::{BlockingMutex, MutexGuard};
pub use waitqueue::WaitQueue;
