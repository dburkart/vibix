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
//! - Per-CPU queues, tickless idle.
//! - Per-task address spaces.
//! - Priority inheritance on blocking primitives (tracked for a later
//!   pass alongside the sleeping-mutex work).
//!
//! Scheduling priorities and UNIX-style nice values are live (see
//! [`priority`] and [`spawn_with_priority`] / [`set_priority`]).
//!
//! Blocking primitives (mutex-that-sleeps, channels, waitqueues) live
//! in [`crate::sync`] and are built on top of [`block_current`] and
//! [`wake`] below.

pub mod priority;
mod scheduler;
mod switch;
mod task;

use alloc::boxed::Box;
use core::sync::atomic::Ordering;
use spin::{Lazy, Mutex};
use x86_64::instructions::interrupts;

pub use priority::{
    clamp_priority, nice_from_priority, priority_from_nice, AFFINITY_ALL, DEFAULT_PRIORITY,
    MAX_PRIORITY, NICE_MAX, NICE_MIN,
};

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

/// Queue a new task running `entry` at [`DEFAULT_PRIORITY`]. The task
/// starts at the back of its priority's ready FIFO and will run when
/// scheduling reaches it.
pub fn spawn(entry: fn() -> !) {
    spawn_with_priority(entry, DEFAULT_PRIORITY);
}

/// Like [`spawn`] but starts the task at a caller-chosen priority.
/// Values above [`MAX_PRIORITY`] are clamped.
pub fn spawn_with_priority(entry: fn() -> !, priority: u8) {
    let task = Box::new(Task::new_with_priority(entry, priority));
    let new_prio = task.priority;
    let mut sched = SCHED.lock();
    sched.push_ready(task);
    maybe_preempt_current_for_priority(&mut sched, new_prio);
}

/// Like [`spawn_with_priority`] but accepts a UNIX-style nice value
/// (`-20..=19`). Wrapper for API ergonomics — mapping lives in
/// [`priority_from_nice`].
pub fn spawn_with_nice(entry: fn() -> !, nice: i8) {
    spawn_with_priority(entry, priority_from_nice(nice));
}

/// Update the priority of task `id` in place. Takes effect on the next
/// scheduling decision: if the task is currently ready it moves to the
/// correct priority bucket; if it is running and its priority dropped
/// below another ready task, the current slice is ended so the higher-
/// priority task preempts at the next tick.
///
/// Returns `true` if a task with `id` was found, `false` otherwise.
pub fn set_priority(id: usize, priority: u8) -> bool {
    let priority = clamp_priority(priority);
    let was_on = interrupts::are_enabled();
    interrupts::disable();
    let mut sched = SCHED.lock();

    let found = apply_priority(&mut sched, id, priority);
    if found {
        // If a ready task now outranks the running one, shorten its slice
        // so the next tick swaps it out.
        preempt_if_higher_ready(&mut sched);
    }

    drop(sched);
    if was_on {
        interrupts::enable();
    }
    found
}

/// Like [`set_priority`] but with a nice-value argument. Returns
/// whether a task with `id` was found.
pub fn set_nice(id: usize, nice: i8) -> bool {
    set_priority(id, priority_from_nice(nice))
}

/// Adjust task `id`'s nice value by `delta`, clamped to the legal
/// range. Returns the resulting nice value, or `None` if the id is
/// unknown.
pub fn adjust_nice(id: usize, delta: i8) -> Option<i8> {
    let was_on = interrupts::are_enabled();
    interrupts::disable();
    let mut sched = SCHED.lock();

    let current_prio = find_priority(&sched, id);
    let result = current_prio.map(|prio| {
        let current_nice = nice_from_priority(prio);
        let new_nice =
            (current_nice as i16 + delta as i16).clamp(NICE_MIN as i16, NICE_MAX as i16) as i8;
        let new_prio = priority_from_nice(new_nice);
        apply_priority(&mut sched, id, new_prio);
        new_nice
    });

    if result.is_some() {
        preempt_if_higher_ready(&mut sched);
    }

    drop(sched);
    if was_on {
        interrupts::enable();
    }
    result
}

/// Set the CPU affinity mask of task `id`. Bit `n` set means the task
/// may run on CPU `n`. On the single-CPU kernel the mask is stored but
/// not enforced. Returns `true` if the id was found.
///
/// A mask of `0` is rejected (a task must be runnable somewhere) and
/// returns `false` without modifying the task.
pub fn set_affinity(id: usize, mask: u64) -> bool {
    if mask == 0 {
        return false;
    }
    let was_on = interrupts::are_enabled();
    interrupts::disable();
    let mut sched = SCHED.lock();

    let mut found = false;
    if let Some(cur) = sched.current.as_mut() {
        if cur.id == id {
            cur.affinity = mask;
            found = true;
        }
    }
    if !found {
        'outer: for queue in sched.ready.values_mut() {
            for task in queue.iter_mut() {
                if task.id == id {
                    task.affinity = mask;
                    found = true;
                    break 'outer;
                }
            }
        }
    }
    if !found {
        if let Some(task) = sched.parked.get_mut(&id) {
            task.affinity = mask;
            found = true;
        }
    }

    drop(sched);
    if was_on {
        interrupts::enable();
    }
    found
}

/// Return the current scheduling priority of the currently-running
/// task. Useful for callers that want to spawn a helper at the same
/// or adjusted priority.
pub fn current_priority() -> u8 {
    SCHED
        .lock()
        .current
        .as_ref()
        .map(|t| t.priority)
        .unwrap_or(DEFAULT_PRIORITY)
}

fn find_priority(sched: &Scheduler, id: usize) -> Option<u8> {
    if let Some(cur) = sched.current.as_ref() {
        if cur.id == id {
            return Some(cur.priority);
        }
    }
    for queue in sched.ready.values() {
        for task in queue.iter() {
            if task.id == id {
                return Some(task.priority);
            }
        }
    }
    sched.parked.get(&id).map(|t| t.priority)
}

/// Mutate the stored priority of task `id` across current/ready/parked
/// and re-bucket if it's in the ready bank. Returns `true` on hit.
fn apply_priority(sched: &mut Scheduler, id: usize, new_priority: u8) -> bool {
    if let Some(cur) = sched.current.as_mut() {
        if cur.id == id {
            cur.priority = new_priority;
            return true;
        }
    }

    // Search ready queues; if found, remove and re-bucket at new priority.
    let mut moved: Option<Box<Task>> = None;
    let mut drop_key: Option<u8> = None;
    for (&prio, queue) in sched.ready.iter_mut() {
        if let Some(pos) = queue.iter().position(|t| t.id == id) {
            let mut task = queue.remove(pos).expect("position just confirmed");
            task.priority = new_priority;
            if queue.is_empty() {
                drop_key = Some(prio);
            }
            moved = Some(task);
            break;
        }
    }
    if let Some(k) = drop_key {
        sched.ready.remove(&k);
    }
    if let Some(task) = moved {
        sched.push_ready(task);
        return true;
    }

    if let Some(task) = sched.parked.get_mut(&id) {
        task.priority = new_priority;
        return true;
    }

    false
}

/// If a ready task at `new_prio` outranks the currently-running task,
/// end the current slice so the PIT tick preempts promptly. Must be
/// called with the scheduler lock held.
fn maybe_preempt_current_for_priority(sched: &mut Scheduler, new_prio: u8) {
    let Some(cur) = sched.current.as_mut() else {
        return;
    };
    if new_prio > cur.priority {
        cur.slice_remaining_ms = 0;
    }
}

/// Query the ready bank and shorten the current slice to zero if any
/// ready task outranks the running one. Must be called with the
/// scheduler lock held.
fn preempt_if_higher_ready(sched: &mut Scheduler) {
    let Some(cur) = sched.current.as_ref() else {
        return;
    };
    let cur_prio = cur.priority;
    if sched.highest_ready_priority().is_some_and(|p| p > cur_prio) {
        sched.current.as_mut().unwrap().slice_remaining_ms = 0;
    }
}

/// Public view of a task's scheduling state, used by [`TaskInfo`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskStateView {
    Running,
    Ready,
    Blocked,
}

/// Snapshot of one task's diagnostic-relevant fields. Returned by
/// [`for_each_task`] so callers (e.g. the shell's `tasks` builtin) can
/// enumerate live tasks without touching the scheduler's internals.
#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub id: usize,
    pub slice_remaining_ms: u32,
    pub state: TaskStateView,
    /// Effective priority (`0..=MAX_PRIORITY`). Higher values preempt.
    pub priority: u8,
    /// UNIX-style nice value (`-20..=19`). Derived from `priority`.
    pub nice: i8,
    /// CPU affinity mask (bit `n` = allowed on CPU `n`).
    pub affinity: u64,
}

/// Invoke `f` once per live task: current first, then ready queue in
/// FIFO order, then parked (blocked) tasks in id order. Snapshots the
/// scheduler under lock and drops it before invoking `f`, so the
/// callback is free to touch any other subsystem (including serial I/O
/// and other `task::*` calls).
pub fn for_each_task(mut f: impl FnMut(TaskInfo)) {
    let snapshot: alloc::vec::Vec<TaskInfo> = {
        let sched = SCHED.lock();
        let mut out = alloc::vec::Vec::with_capacity(
            sched.current.is_some() as usize + sched.ready_count() + sched.parked.len(),
        );
        if let Some(cur) = sched.current.as_ref() {
            out.push(TaskInfo {
                id: cur.id,
                slice_remaining_ms: cur.slice_remaining_ms,
                state: TaskStateView::Running,
                priority: cur.priority,
                nice: nice_from_priority(cur.priority),
                affinity: cur.affinity,
            });
        }
        for t in sched.iter_ready() {
            out.push(TaskInfo {
                id: t.id,
                slice_remaining_ms: t.slice_remaining_ms,
                state: TaskStateView::Ready,
                priority: t.priority,
                nice: nice_from_priority(t.priority),
                affinity: t.affinity,
            });
        }
        for t in sched.parked.values() {
            out.push(TaskInfo {
                id: t.id,
                slice_remaining_ms: t.slice_remaining_ms,
                state: TaskStateView::Blocked,
                priority: t.priority,
                nice: nice_from_priority(t.priority),
                affinity: t.affinity,
            });
        }
        out
    };
    for info in snapshot {
        f(info);
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

/// Install a VMA on the currently-running task. The VMA is resolved
/// lazily by the `#PF` handler on first touch of each page.
pub fn install_vma_on_current(vma: crate::mem::vma::Vma) {
    let mut sched = SCHED.lock();
    let current = sched
        .current
        .as_mut()
        .expect("install_vma_on_current: no running task");
    current.vmas.insert(vma);
}

/// Consult the current task's VMA list for `addr`. Returns the VMA's
/// backing kind and the flags the `#PF` resolver should apply.
///
/// Returns `None` if the scheduler lock is contended — the `#PF`
/// handler treats that as "not a demand-page fault" and falls through
/// to the generic hang path. In practice contention only arises when
/// the fault hit mid-`context_switch`; for demand-paged tasks running
/// normally the lock is free at fault time.
pub fn current_vma_lookup(
    addr: usize,
) -> Option<(
    crate::mem::vma::VmaKind,
    x86_64::structures::paging::PageTableFlags,
)> {
    let sched = SCHED.try_lock()?;
    let current = sched.current.as_ref()?;
    let vma = current.vmas.find(addr)?;
    Some((vma.kind, vma.flags))
}

/// Terminate the currently-running task. Reclaims the task's mapped
/// stack pages, VMA-backed frames, and PML4 frame on the next
/// scheduler tick, then drops the `Box<Task>`.
///
/// The actual reclaim runs from [`preempt_tick`] rather than here
/// because it unmaps the very stack we're executing on — we have to
/// context-switch away first. The exiting task is parked in
/// `Scheduler::pending_exit` for the next tick to reap.
///
/// The stack VA slot (`NEXT_STACK_VA`'s bump-allocated range) is *not*
/// reclaimed — that would require a free-list on `NEXT_STACK_VA`
/// which is out of scope for this pass. The VA is logged as leaked.
///
/// # Panics
/// - No other ready task exists (exiting the last runnable task would
///   halt the kernel).
/// - A prior `task::exit` has not yet been reaped. At most one task
///   may be awaiting reap at a time; with reaping on every tick this
///   only trips if the scheduler lock is so contended that no tick
///   ever reaps — i.e. never, in practice.
pub fn exit() -> ! {
    interrupts::disable();
    let (prev_rsp_ptr, next_rsp, next_cr3) = {
        let mut sched = SCHED.lock();
        assert!(
            sched.pending_exit.is_none(),
            "task::exit: prior exit not yet reaped"
        );
        let Some(mut next) = sched.pop_highest() else {
            panic!("task::exit: no ready task to switch to");
        };
        let prev = sched.current.take().expect("task::exit before task::init");
        next.state = TaskState::Running;
        let next_rsp = next.rsp;
        let next_cr3 = next.cr3.start_address().as_u64();
        sched.current = Some(next);
        sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
        sched.pending_exit = Some(prev);
        let prev_ref = sched.pending_exit.as_mut().unwrap();
        // SAFETY: prev_ref is a stable Box<Task> in pending_exit; the
        // heap-allocated Task it points at does not move while the
        // Box lives, and context_switch only writes to this location
        // once (we never read it back — the task is doomed).
        let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;
        (prev_rsp_ptr, next_rsp, next_cr3)
    };
    // SAFETY: IRQs are masked, SCHED is dropped, prev_rsp_ptr targets
    // a stable heap location, next_cr3 is a valid per-task PML4.
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp, next_cr3);
    }
    unreachable!("task::exit returned from context_switch");
}

/// Reclaim the stack pages, VMA-backed frames, and PML4 frame of a
/// task that called [`exit`]. Called from [`preempt_tick`] on a stack
/// that is *not* the victim's — the victim already context-switched
/// away, so unmapping its stack is safe.
fn reap_pending(victim: alloc::boxed::Box<Task>) {
    use crate::mem::paging;
    use crate::mem::vma::VmaKind;
    use x86_64::structures::paging::{FrameDeallocator, Page, Size4KiB};
    use x86_64::VirtAddr;

    // 1. Unmap + free stack pages. These live in the shared upper-half
    //    kernel window (L4 entry 416), so a single unmap via the
    //    active PML4 propagates through aliasing to every PML4.
    let stack_base = victim.stack_base();
    if stack_base != 0 {
        for i in 0..victim.stack_page_count() {
            let va = stack_base + i * 4096;
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64))
                .expect("stack page VA aligned by construction");
            let _ = paging::unmap_and_free(page);
        }
    }

    // 2. Walk VMAs. For each VA in each VMA, unmap from the victim's
    //    private PML4. AnonZero: free the frame. Cow: free only when
    //    the backing frame is not the shared source (the private
    //    post-write copy).
    for vma in victim.vmas.iter() {
        let mut va = vma.start;
        while va < vma.end {
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64))
                .expect("vma page VA aligned by construction");
            match vma.kind {
                VmaKind::AnonZero => {
                    let _ = paging::unmap_and_free_in_pml4(victim.cr3, page);
                }
                VmaKind::Cow { frame: source } => {
                    if let Ok(frame) = paging::unmap_in_pml4(victim.cr3, page) {
                        if frame != source {
                            // SAFETY: private copy allocated from the
                            // global allocator by the #PF resolver.
                            unsafe {
                                paging::KernelFrameAllocator.deallocate_frame(frame);
                            }
                        }
                    }
                }
            }
            va += 4096;
        }
    }

    // 3. Return the PML4 frame itself.
    // SAFETY: victim is no longer on any CPU; we're running on a
    //         different CR3 and no other reference to its PML4
    //         survives — the Box<Task> is about to be dropped.
    unsafe { paging::free_pml4_frame(victim.cr3) };

    // 4. Log the leaked stack VA slot for diagnostics.
    if stack_base != 0 {
        serial_println!(
            "tasks: reaped task {} (stack VA slot {:#x}..{:#x} leaked)",
            victim.id,
            victim.guard_base,
            victim.guard_base + task::TASK_SLOT_SIZE
        );
    }

    // 5. Drop the Box<Task>, returning its heap memory.
    drop(victim);
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

    // Reap a task that called `task::exit` on a prior tick, before
    // touching the ready bank — keeps this tick's rotation consistent
    // and bounds pending_exit to at most one tick of latency.
    if let Some(victim) = sched.pending_exit.take() {
        drop(sched);
        reap_pending(victim);
        let Some(s) = SCHED.try_lock() else {
            return;
        };
        sched = s;
    }

    // No task::init yet (or a non-task integration test) — nothing to
    // preempt. Forces Lazy init, but that's allocation-free.
    if sched.current.is_none() {
        return;
    }

    // Drain any tick-deadline wakeups (see `task::sleep_ms`) and
    // promote their targets. Runs before the preemption decision so a
    // freshly-unparked task is visible in the highest-ready check.
    for id in crate::time::drain_expired(crate::time::ticks()) {
        wake_in_sched(&mut sched, id);
    }

    {
        let top_ready = sched.highest_ready_priority();
        let current = sched.current.as_mut().unwrap();
        current.slice_remaining_ms = current.slice_remaining_ms.saturating_sub(TICK_MS as u32);
        // Preempt immediately if something at strictly higher priority
        // is ready. Otherwise keep running until the slice expires; when
        // it does, only rotate if a peer at the same priority is ready
        // — handing off to a strictly lower-priority task would defeat
        // the whole point of priorities.
        let higher_ready = top_ready.is_some_and(|p| p > current.priority);
        let peer_ready = top_ready.is_some_and(|p| p == current.priority);
        if !higher_ready && (current.slice_remaining_ms > 0 || !peer_ready) {
            if current.slice_remaining_ms == 0 {
                current.slice_remaining_ms = DEFAULT_SLICE_MS;
            }
            return;
        }
    }

    let Some(mut next) = sched.pop_highest() else {
        // Shouldn't happen: the guard above already returned when the
        // ready bank was empty. Reload defensively.
        sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
        return;
    };

    let mut prev = sched.current.take().unwrap();
    prev.state = TaskState::Ready;
    next.state = TaskState::Running;
    let next_rsp = next.rsp;
    let next_cr3 = next.cr3.start_address().as_u64();
    let prev_prio = prev.priority;
    sched.current = Some(next);
    sched.current.as_mut().unwrap().slice_remaining_ms = DEFAULT_SLICE_MS;
    sched.push_ready(prev);
    // The push above put `prev` at the back of its priority's queue;
    // retrieve the pointer through the bank to keep the Box-stability
    // invariant.
    let prev_ref = sched
        .ready
        .get_mut(&prev_prio)
        .and_then(|q| q.back_mut())
        .expect("just pushed");
    let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;
    drop(sched);

    // SAFETY: `prev_rsp_ptr` points at the `rsp` field of a Box<Task>
    // in the ready queue. The Box indirection pins the Task's address
    // — a VecDeque reallocation would move the Box, not the heap-
    // allocated Task it points at — so the pointer stays valid even
    // though the VecDeque could mutate from under us. IRQs are already
    // masked inside the ISR, so no other scheduler path can race us
    // between lock drop and the context switch. `next_cr3` is a valid
    // PML4 whose upper half mirrors the kernel PML4 (by construction
    // in `Task::new` / `Task::bootstrap`).
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp, next_cr3);
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

    let (prev_rsp_ptr, next_rsp, next_cr3) = {
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

        let Some(mut next) = sched.pop_highest() else {
            panic!("task::block_current: no ready task to switch to");
        };
        let mut prev = sched.current.take().unwrap();
        prev.state = TaskState::Blocked;
        next.state = TaskState::Running;
        let prev_id = prev.id;
        let next_rsp = next.rsp;
        let next_cr3 = next.cr3.start_address().as_u64();
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

        (prev_rsp_ptr, next_rsp, next_cr3)
    };

    // SAFETY: IRQs are masked, the SCHED lock is dropped so the
    // incoming task can re-enter the scheduler, and prev_rsp_ptr
    // targets stable heap memory (see the insert comment above).
    // `next_cr3` is a valid per-task PML4 (see preempt_tick).
    unsafe {
        context_switch(prev_rsp_ptr, next_rsp, next_cr3);
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
    wake_in_sched(&mut sched, id);
    drop(sched);

    if was_on {
        interrupts::enable();
    }
}

/// Body of [`wake`] that operates on a caller-held scheduler lock.
/// Used by [`preempt_tick`] after draining tick-deadline wakeups so the
/// unpark happens without re-entering the mutex.
fn wake_in_sched(sched: &mut Scheduler, id: usize) {
    // Parked → Ready is the happy path.
    if let Some(mut task) = sched.parked.remove(&id) {
        task.state = TaskState::Ready;
        task.slice_remaining_ms = DEFAULT_SLICE_MS;
        let prio = task.priority;
        sched.push_ready(task);
        maybe_preempt_current_for_priority(sched, prio);
        return;
    }

    // Task is Running or Ready. Set wake_pending so the next
    // block_current call on it returns immediately — this is the
    // wake-before-park race cure (see `block_current`'s fast path).
    if let Some(current) = sched.current.as_ref() {
        if current.id == id {
            current.wake_pending.store(true, Ordering::Release);
            return;
        }
    }
    let _ = sched.iter_ready().any(|task| {
        if task.id == id {
            task.wake_pending.store(true, Ordering::Release);
            true
        } else {
            false
        }
    });
    // Unknown id — drop on the floor.
}

/// Park the current task for at least `ms` milliseconds.
///
/// Computes a deadline in PIT ticks (ceil-div against [`TICK_MS`] so a
/// short sleep never returns early), registers the current task id
/// with the time subsystem, and parks via [`block_current`]. The PIT
/// ISR drains expired deadlines and unparks through the normal
/// scheduler path.
///
/// Resolution is the PIT tick (10 ms at 100 Hz); callers asking for
/// less will sleep for at least one full tick.
pub fn sleep_ms(ms: u64) {
    let ticks_to_wait = ms.div_ceil(crate::time::TICK_MS).max(1);
    let deadline = crate::time::ticks().saturating_add(ticks_to_wait);
    let id = current_id();
    crate::time::enqueue_wakeup(deadline, id);
    block_current();
}
