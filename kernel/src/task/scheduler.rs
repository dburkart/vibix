//! Round-robin scheduler state. Holds the currently-running task and
//! a FIFO ready queue. Rescheduling happens from either `yield_now()`
//! (cooperative) or `preempt_tick()` (PIT ISR); `yield_now` masks IRQs
//! across the lock/switch window so the two paths can't race on the
//! queue.

use alloc::boxed::Box;
use alloc::collections::VecDeque;

use super::task::Task;

pub(super) struct Scheduler {
    pub current: Option<Box<Task>>,
    pub ready: VecDeque<Box<Task>>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            current: None,
            ready: VecDeque::new(),
        }
    }
}
