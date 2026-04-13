//! Priority-aware scheduler state. Holds the currently-running task, a
//! per-priority FIFO ready queue bank, and a side-table of blocked
//! (parked) tasks.
//!
//! Rescheduling happens from either `preempt_tick()` (PIT ISR, on
//! slice exhaustion or when a higher-priority task becomes ready) or
//! `block_current()` (task voluntarily parking on a waitqueue). Both
//! paths lock the scheduler, update the queues, then drop the lock
//! before `context_switch` to avoid deadlocking the incoming task's
//! own scheduler entry.
//!
//! The ready bank is a `BTreeMap<u8, VecDeque<Box<Task>>>` keyed by
//! priority. `pick_next` drains highest priority first; within a level
//! tasks rotate in FIFO order. Empty priority queues are dropped from
//! the map, so iteration cost scales with the number of *distinct*
//! priorities currently runnable rather than the full 40-entry range.
//!
//! Blocked tasks are parked in `parked` (keyed by task id) and are
//! invisible to the scheduling rotation. `task::wake(id)` migrates
//! them back to `ready`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};

use super::task::Task;

pub(super) struct Scheduler {
    pub current: Option<Box<Task>>,
    /// Ready tasks grouped by priority. Higher keys run first; within a
    /// level the `VecDeque` is a FIFO ring for round-robin rotation.
    /// Invariant: every value is a non-empty `VecDeque` — an empty
    /// queue is removed from the map so `highest_ready_priority` can
    /// rely on the last key being actually runnable.
    pub ready: BTreeMap<u8, VecDeque<Box<Task>>>,
    /// Tasks that have called `block_current` and are waiting to be
    /// unparked by `wake(id)`. Keyed by task id for O(log n) lookup.
    /// Blocking primitives (see `crate::sync`) move tasks in and out
    /// of here via the task-level API.
    pub parked: BTreeMap<usize, Box<Task>>,
    /// A task that has called `task::exit` and is awaiting reaping on
    /// the next scheduler tick. At most one at a time — `task::exit`
    /// refuses to enter if the slot is occupied. The reaper runs from
    /// `preempt_tick` (so it executes on a stack that isn't about to be
    /// unmapped) and drops the `Box<Task>` after reclaiming the stack
    /// pages, VMA-backed frames, and PML4 frame.
    pub pending_exit: Option<Box<Task>>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            current: None,
            ready: BTreeMap::new(),
            parked: BTreeMap::new(),
            pending_exit: None,
        }
    }

    /// Enqueue `task` at the back of its priority's ready FIFO.
    pub fn push_ready(&mut self, task: Box<Task>) {
        self.ready.entry(task.priority).or_default().push_back(task);
    }

    /// Pop the highest-priority ready task, or `None` if nothing is
    /// runnable. Removes empty buckets as it goes to uphold the
    /// non-empty invariant.
    pub fn pop_highest(&mut self) -> Option<Box<Task>> {
        let highest = *self.ready.keys().next_back()?;
        let queue = self.ready.get_mut(&highest)?;
        let task = queue.pop_front();
        if queue.is_empty() {
            self.ready.remove(&highest);
        }
        task
    }

    /// Highest priority currently runnable in the ready bank, or
    /// `None` if the bank is empty.
    pub fn highest_ready_priority(&self) -> Option<u8> {
        self.ready.keys().next_back().copied()
    }

    /// Total number of ready tasks across all priority buckets.
    pub fn ready_count(&self) -> usize {
        self.ready.values().map(|q| q.len()).sum()
    }

    /// Iterate ready tasks in scheduling order (highest priority first,
    /// FIFO within a level). Exposed for snapshots in `for_each_task`.
    pub fn iter_ready(&self) -> impl Iterator<Item = &Box<Task>> {
        self.ready.values().rev().flat_map(|q| q.iter())
    }
}
