//! Round-robin scheduler state. Holds the currently-running task and
//! a FIFO ready queue. Cooperative only — `yield_now()` is the sole
//! rescheduling point, so we don't need to worry about IRQs mutating
//! the queue mid-switch.

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
