//! Cooperative kernel tasks.
//!
//! A minimal round-robin scheduler with a single ready queue and no
//! preemption — tasks hand control back only by calling [`yield_now`].
//! Each task owns a heap-allocated kernel stack and a saved register
//! context; the hand-written switch in [`switch`] is the one place
//! that touches `rsp`.
//!
//! ## Ordering
//!
//! [`init`] must be called after `mem::init()` (we allocate on the
//! heap) and after interrupts are enabled in `main` — `vibix::init()`
//! deliberately stays single-threaded so integration tests that don't
//! care about tasks keep their simple `_start` flow.
//!
//! ## What's *not* here (yet)
//!
//! - Preemption (M6 lands a timer-driven switch).
//! - Blocking primitives — cooperative code polls + yields.
//! - Per-task address spaces or guard pages.

mod scheduler;
mod switch;
mod task;

use alloc::boxed::Box;
use spin::{Lazy, Mutex};

use scheduler::Scheduler;
use switch::context_switch;
use task::Task;

use crate::serial_println;

static SCHED: Lazy<Mutex<Scheduler>> = Lazy::new(|| Mutex::new(Scheduler::new()));

/// Install the bootstrap task wrapping the currently-running thread.
/// Must be called exactly once, before any [`spawn`] or [`yield_now`].
pub fn init() {
    let mut sched = SCHED.lock();
    assert!(sched.current.is_none(), "task::init called twice");
    sched.current = Some(Box::new(Task::bootstrap()));
    drop(sched);
    serial_println!("tasks: scheduler online");
}

/// Queue a new task running `entry`. The task starts at the back of
/// the ready queue and will run when scheduling reaches it.
pub fn spawn(entry: fn() -> !) {
    let mut sched = SCHED.lock();
    sched.ready.push_back(Box::new(Task::new(entry)));
}

/// Yield the CPU to the next runnable task. If no other task is
/// ready, returns immediately. Safe to call from any task (including
/// the bootstrap task after [`init`]).
pub fn yield_now() {
    // Carve out the switch parameters under the lock, then drop the
    // lock BEFORE the context switch. Holding it across would
    // deadlock the incoming task's own call to `yield_now`.
    let (prev_rsp_ptr, next_rsp) = {
        let mut sched = SCHED.lock();
        let Some(next) = sched.ready.pop_front() else {
            return;
        };
        let prev = sched.current.take().expect("yield_now before task::init");

        let next_rsp = next.rsp;
        sched.current = Some(next);
        sched.ready.push_back(prev);
        let prev_ref = sched.ready.back_mut().expect("just pushed");
        let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;

        (prev_rsp_ptr, next_rsp)
    };

    // SAFETY: `prev_rsp_ptr` points at the `rsp` field of a Box<Task>
    // in the ready queue. The Box indirection pins the Task's address
    // — a VecDeque reallocation would move the Box, not the Task
    // itself — so the pointer stays valid even if an IRQ fires before
    // `context_switch` reaches its write. The Task can't be dropped
    // until someone re-acquires SCHED and pops it, which can't happen
    // between this lock drop and that write on a single CPU. This
    // relies on no IRQ handler calling `spawn`/`yield_now`; the
    // current timer + keyboard handlers don't.
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp);
    }
}
