//! Round-robin kernel tasks, cooperative + PIT-driven preemption.
//!
//! Tasks can hand control back explicitly with [`yield_now`], and the
//! timer ISR calls [`preempt_tick`] every PIT interrupt to rotate tasks
//! that never yield. Each task owns a guard-paged kernel stack and a
//! saved register context; the hand-written switch in [`switch`] is the
//! one place that touches `rsp`.
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
//! - Blocking primitives — cooperative code polls + yields.
//! - Per-task address spaces.

mod scheduler;
mod switch;
mod task;

use alloc::boxed::Box;
use spin::{Lazy, Mutex};
use x86_64::instructions::interrupts;

use scheduler::Scheduler;
use switch::context_switch;
use task::Task;

use crate::serial_println;
use crate::time::TICK_MS;

/// Default time slice, in milliseconds. At 100 Hz this lines up with a
/// single PIT tick — every tick is a rescheduling opportunity.
pub(crate) const DEFAULT_SLICE_MS: u32 = 10;

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
    // Mask IRQs across the lock + switch so the timer ISR's preempt
    // path can't mutate the ready queue between our lock drop and the
    // context_switch (which would invalidate `prev_rsp_ptr`). `was_on`
    // lives on this task's stack — when we're eventually switched back
    // in, it'll be restored and we re-enable iff this task was running
    // with IRQs on. Tasks first entered via the trampoline always come
    // back here with IRQs on, regardless of our caller's state.
    let was_on = interrupts::are_enabled();
    interrupts::disable();

    // Carve out the switch parameters under the lock, then drop the
    // lock BEFORE the context switch. Holding it across would
    // deadlock the incoming task's own call to `yield_now`.
    let (prev_rsp_ptr, next_rsp) = {
        let mut sched = SCHED.lock();
        let Some(next) = sched.ready.pop_front() else {
            if was_on {
                interrupts::enable();
            }
            return;
        };
        let prev = sched.current.take().expect("yield_now before task::init");

        let next_rsp = next.rsp;
        sched.current = Some(next);
        sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
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
    // between this lock drop and that write on a single CPU. We've
    // also masked IRQs for the duration, so the preempt tick can't
    // fire and re-enter the scheduler while the switch is in flight.
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp);
    }

    if was_on {
        interrupts::enable();
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
/// cooperative switch.
///
/// Runs with IRQs masked (interrupt gate). The switched-in task
/// resumes either via IRET (if it was last preempted) or through
/// `yield_now`'s tail (if it was last suspended cooperatively) — both
/// paths restore a correct IF on return to task code.
pub fn preempt_tick() {
    // `try_lock` + bail: yield_now (or another preempt tick mid-switch)
    // may already hold SCHED. We'll get another tick in 10 ms.
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

    let Some(next) = sched.ready.pop_front() else {
        // Slice expired but nobody else is ready. Reload and keep
        // running — prevents repeated try_lock churn on every tick.
        sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
        return;
    };

    let prev = sched.current.take().unwrap();
    let next_rsp = next.rsp;
    sched.current = Some(next);
    sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
    sched.ready.push_back(prev);
    let prev_ref = sched.ready.back_mut().expect("just pushed");
    let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;
    drop(sched);

    // SAFETY: same invariant as `yield_now` — `prev_rsp_ptr` stays
    // valid because Box pins the Task's address, and IRQs are masked
    // inside the ISR so no other scheduler path can race us between
    // lock drop and the context switch.
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp);
    }
}
