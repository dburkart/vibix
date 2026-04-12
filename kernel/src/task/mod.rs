//! Round-robin kernel tasks, preemptively scheduled off the PIT tick.
//!
//! The timer ISR calls [`preempt_tick`] every PIT interrupt; once the
//! running task's time slice is exhausted, the scheduler rotates to
//! the next task in the ready queue. Tasks that want to block on a
//! condition call [`block_current`] (via [`crate::sync`]); tasks that
//! have nothing to do halt and let the next timer IRQ either resume
//! them or switch to something else.
//!
//! Each task owns a guard-paged kernel stack and a saved register
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
//! - Priorities, per-CPU queues, tickless idle.
//! - Per-task address spaces.
//!
//! Blocking primitives (mutex-that-sleeps, channels, waitqueues) live
//! in [`crate::sync`] and are built on top of [`block_current`] and
//! [`wake`] below.

mod scheduler;
mod switch;
mod task;

use alloc::boxed::Box;
use core::sync::atomic::Ordering;
use spin::{Lazy, Mutex};
use x86_64::instructions::interrupts;

use scheduler::Scheduler;
use switch::context_switch;
use task::{Task, TaskState};

use crate::serial_println;
use crate::time::TICK_MS;

/// Default time slice, in milliseconds. At 100 Hz this lines up with a
/// single PIT tick — every tick is a rescheduling opportunity.
pub(crate) const DEFAULT_SLICE_MS: u32 = 10;

static SCHED: Lazy<Mutex<Scheduler>> = Lazy::new(|| Mutex::new(Scheduler::new()));

/// Install the bootstrap task wrapping the currently-running thread.
/// Must be called exactly once, before any [`spawn`].
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

/// Snapshot of one task's diagnostic-relevant fields. Returned by
/// [`for_each_task`] so callers (e.g. the shell's `tasks` builtin) can
/// enumerate live tasks without touching the scheduler's internals.
#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub id: usize,
    pub slice_remaining_ms: u32,
    /// `true` for the currently-running task, `false` for ready-queue entries.
    pub is_current: bool,
}

/// Invoke `f` once per live task (current first, then ready queue in
/// FIFO order). Holds the scheduler lock for the duration, so `f` must
/// not call back into `task::*`.
pub fn for_each_task(mut f: impl FnMut(TaskInfo)) {
    let sched = SCHED.lock();
    if let Some(cur) = sched.current.as_ref() {
        f(TaskInfo {
            id: cur.id,
            slice_remaining_ms: cur.slice_remaining_ms,
            is_current: true,
        });
    }
    for t in sched.ready.iter() {
        f(TaskInfo {
            id: t.id,
            slice_remaining_ms: t.slice_remaining_ms,
            is_current: false,
        });
    }
}

/// Check whether `addr` falls within any live kernel task's guard page.
/// Returns the task ID of the overflowing task, or `None` if no guard
/// page was hit.
///
/// Fully lock-free: derives the answer from the fixed VA layout of the
/// task stack window, so it is always safe to call from any exception
/// context — even when the scheduler lock is already held on this CPU.
pub fn find_stack_overflow(addr: usize) -> Option<usize> {
    use core::sync::atomic::Ordering;
    use task::{GUARD_SIZE, NEXT_STACK_VA, TASK_SLOT_SIZE, TASK_STACKS_VA_BASE};

    let next_va = NEXT_STACK_VA.load(Ordering::Relaxed);
    if addr < TASK_STACKS_VA_BASE || addr >= next_va {
        return None;
    }
    let slot_idx = (addr - TASK_STACKS_VA_BASE) / TASK_SLOT_SIZE;
    let slot_guard_base = TASK_STACKS_VA_BASE + slot_idx * TASK_SLOT_SIZE;
    // Guard page occupies [slot_guard_base, slot_guard_base + GUARD_SIZE).
    // Task IDs start at 1, so slot 0 → task 1.
    if addr < slot_guard_base + GUARD_SIZE {
        Some(slot_idx + 1)
    } else {
        None
    }
}

/// Called from the timer ISR after `notify_eoi`. Decrements the
/// current task's slice; if it's exhausted and there's another task
/// ready, rotates and context-switches. Bails on lock contention so
/// the ISR never blocks on a task that's in the middle of its own
/// [`block_current`] switch.
///
/// Runs with IRQs masked (interrupt gate). The switched-in task
/// resumes either via IRET (if it was last preempted at tick time)
/// or through [`block_current`]'s tail (if it was last suspended on
/// a waitqueue); both paths restore a correct IF on return to task
/// code.
pub fn preempt_tick() {
    // `try_lock` + bail: block_current (or another preempt tick
    // mid-switch) may already hold SCHED. We'll get another tick in
    // 10 ms.
    let Some(mut sched) = SCHED.try_lock() else {
        return;
    };

    // No task::init yet (or a non-task integration test) — nothing to
    // preempt. Forces Lazy init, but that's allocation-free.
    if sched.current.is_none() {
        return;
    }

    {
        let current = sched.current.as_mut().unwrap();
        current.slice_remaining_ms = current.slice_remaining_ms.saturating_sub(TICK_MS as u32);
        if current.slice_remaining_ms > 0 {
            return;
        }
    }

    let Some(mut next) = sched.ready.pop_front() else {
        // Slice expired but nobody else is ready. Reload and keep
        // running — prevents repeated try_lock churn on every tick.
        sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
        return;
    };

    let mut prev = sched.current.take().unwrap();
    prev.state = TaskState::Ready;
    next.state = TaskState::Running;
    let next_rsp = next.rsp;
    sched.current = Some(next);
    sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
    sched.ready.push_back(prev);
    let prev_ref = sched.ready.back_mut().expect("just pushed");
    let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;
    drop(sched);

    // SAFETY: `prev_rsp_ptr` points at the `rsp` field of a Box<Task>
    // in the ready queue. The Box indirection pins the Task's address
    // — a VecDeque reallocation would move the Box, not the heap-
    // allocated Task it points at — so the pointer stays valid even
    // though the VecDeque could mutate from under us. IRQs are already
    // masked inside the ISR, so no other scheduler path can race us
    // between lock drop and the context switch.
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp);
    }
}

/// Return the id of the currently-running task.
///
/// Must be called after [`init`]. Briefly locks the scheduler, so do
/// not call from an ISR context or while holding any lock whose
/// ordering places it *after* `SCHED`.
pub fn current_id() -> usize {
    SCHED
        .lock()
        .current
        .as_ref()
        .expect("current_id before task::init")
        .id
}

/// Block the current task until some later [`wake`] call with its id.
///
/// Callers are responsible for registering the current task with a
/// wakeup source (e.g. pushing their id onto a
/// [`crate::sync::WaitQueue`]) *before* invoking this function — see
/// [`crate::sync::WaitQueue::wait_while`] for the standard pattern.
///
/// The function is race-free against a [`wake`] call that fires
/// between "register" and "block": [`wake`] sets the target task's
/// `wake_pending` flag if the task is still Running or Ready, and the
/// fast path here consumes the flag and returns without parking.
///
/// # Panics
///
/// Panics if there is no other task in the ready queue — blocking the
/// sole runnable task would halt the kernel forever. In practice the
/// bootstrap task is always ready, so this only fires if something
/// genuinely wedged the scheduler.
pub fn block_current() {
    let was_on = interrupts::are_enabled();
    interrupts::disable();

    let (prev_rsp_ptr, next_rsp) = {
        let mut sched = SCHED.lock();

        // Fast path: a prior wake() set wake_pending while we were
        // still Running. Clear and return without parking — this
        // closes the wake-before-park race.
        //
        // AcqRel on swap: Acquire pairs with wake()'s Release store so
        // anything the waker published before setting the flag is
        // visible to us; Release on the clear keeps later reads (e.g.
        // the condition in wait_while) from being hoisted above this
        // point.
        if sched
            .current
            .as_ref()
            .expect("block_current before task::init")
            .wake_pending
            .swap(false, Ordering::AcqRel)
        {
            drop(sched);
            if was_on {
                interrupts::enable();
            }
            return;
        }

        let Some(mut next) = sched.ready.pop_front() else {
            panic!("task::block_current: no ready task to switch to");
        };
        let mut prev = sched.current.take().unwrap();
        prev.state = TaskState::Blocked;
        next.state = TaskState::Running;
        let prev_id = prev.id;
        let next_rsp = next.rsp;
        sched.current = Some(next);
        sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
        sched.parked.insert(prev_id, prev);

        let prev_ref = sched
            .parked
            .get_mut(&prev_id)
            .expect("just inserted into parked");
        // SAFETY: `prev_ref` is `&mut Box<Task>`; the Box heap-allocates
        // the Task, so `&mut prev_ref.rsp` points at stable memory that
        // survives any BTreeMap rebalance (rebalancing moves the Box,
        // not the heap-allocated Task it points at). Same invariant as
        // preempt_tick's ready-queue push.
        let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;

        (prev_rsp_ptr, next_rsp)
    };

    // SAFETY: IRQs are masked, the SCHED lock is dropped so the
    // incoming task can re-enter the scheduler, and prev_rsp_ptr
    // targets stable heap memory (see the insert comment above).
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp);
    }

    if was_on {
        interrupts::enable();
    }
}

/// Unpark the task with id `id`, or record a pending wake if the task
/// is still Running / Ready so that its next [`block_current`] call
/// returns without parking.
///
/// Task-context only. The scheduler lock is the same one `preempt_tick`
/// uses with `try_lock`, so calling this from an ISR is a deadlock risk
/// if the ISR interrupts a task already holding it. If you need an
/// ISR-originating wake, defer it through a lock-free queue drained by
/// a kernel task — the keyboard input ring is the pattern.
///
/// A wake on an unknown id (task exited — which M6 doesn't have yet —
/// or never existed) is silently ignored.
pub fn wake(id: usize) {
    let was_on = interrupts::are_enabled();
    interrupts::disable();

    let mut sched = SCHED.lock();

    // Parked → Ready is the happy path: move the Box across and hand
    // the task a fresh slice so it gets a full tick the next time the
    // scheduler rotates through.
    if let Some(mut task) = sched.parked.remove(&id) {
        task.state = TaskState::Ready;
        task.slice_remaining_ms = DEFAULT_SLICE_MS;
        sched.ready.push_back(task);
        drop(sched);
        if was_on {
            interrupts::enable();
        }
        return;
    }

    // Task is Running or Ready. Set wake_pending so the next
    // block_current call on it returns immediately. This is the
    // wake-before-park race cure — see `block_current`'s fast path.
    if let Some(current) = sched.current.as_ref() {
        if current.id == id {
            current.wake_pending.store(true, Ordering::Release);
            drop(sched);
            if was_on {
                interrupts::enable();
            }
            return;
        }
    }
    for task in sched.ready.iter() {
        if task.id == id {
            task.wake_pending.store(true, Ordering::Release);
            drop(sched);
            if was_on {
                interrupts::enable();
            }
            return;
        }
    }

    // Unknown id — drop the wake on the floor. Tasks don't exit yet so
    // this only fires if somebody handed us a stale or invented id.
    drop(sched);
    if was_on {
        interrupts::enable();
    }
}
