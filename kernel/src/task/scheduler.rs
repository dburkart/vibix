//! Round-robin scheduler state. Holds the currently-running task, a
//! FIFO ready queue, and a side-table of blocked (parked) tasks.
//!
//! Rescheduling happens from either `preempt_tick()` (PIT ISR, on
//! slice exhaustion) or `block_current()` (task voluntarily parking
//! on a waitqueue). Both paths lock the scheduler, update the queues,
//! then drop the lock before `context_switch` to avoid deadlocking
//! the incoming task's own scheduler entry.
//!
//! Blocked tasks are parked in `parked` (keyed by task id) and are
//! invisible to the round-robin rotation. `task::wake(id)` migrates
//! them back to `ready`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};

use super::task::Task;

pub(super) struct Scheduler {
    pub current: Option<Box<Task>>,
    pub ready: VecDeque<Box<Task>>,
    /// Tasks that have called `block_current` and are waiting to be
    /// unparked by `wake(id)`. Keyed by task id for O(log n) lookup.
    /// Blocking primitives (see `crate::sync`) move tasks in and out
    /// of here via the task-level API.
    pub parked: BTreeMap<usize, Box<Task>>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            current: None,
            ready: VecDeque::new(),
            parked: BTreeMap::new(),
        }
    }
}
