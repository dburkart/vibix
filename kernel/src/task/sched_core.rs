//! Scheduler core: the bare-metal-only contents of `task::mod` extracted
//! into its own file so `task::env` can stay host-buildable behind the
//! `sched-mock` feature gate (RFC 0005 wave 3, #668).
//!
//! Everything in this file is `cfg(target_os = "none")`-gated by its
//! parent module declaration; the imports below are only legal on the
//! bare-metal target.

use super::env;
use super::priority;
use super::softirq;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::sync::atomic::Ordering;
use spin::{Lazy, Mutex};
use x86_64::instructions::interrupts;

use crate::sync::IrqLock;

use crate::sync::WaitQueue;

pub use priority::{
    clamp_priority, nice_from_priority, priority_from_nice, AFFINITY_ALL, DEFAULT_PRIORITY,
    MAX_PRIORITY, NICE_MAX, NICE_MIN,
};

use super::scheduler::Scheduler;
use super::switch::context_switch;
use super::task::{Task, TaskState};

use crate::arch::x86_64::fpu;
use crate::serial_println;
use crate::time::TICK_MS;

/// Default time slice, in milliseconds. At 100 Hz this lines up with a
/// single PIT tick — every tick is a rescheduling opportunity.
pub(crate) const DEFAULT_SLICE_MS: u32 = 10;

static SCHED: Lazy<IrqLock<Scheduler>> = Lazy::new(|| IrqLock::new(Scheduler::new()));

/// Victims produced by [`exit`] waiting for the reaper task to reclaim
/// them. Holds the `Box<Task>` so the task's stack, address space, and
/// FPU area stay pinned until the reaper runs in task context — where
/// it is safe to take the blocking frame-allocator and HHDM locks.
///
/// Uses a plain `spin::Mutex` (not `BlockingMutex`) so `exit` can push
/// a victim with IRQs masked without risking a park. The critical
/// section is a single `push_back`, the only other accessor is the
/// reaper's drain, and contention is bounded by the exit rate.
static REAPER_VICTIMS: Mutex<VecDeque<Box<Task>>> = Mutex::new(VecDeque::new());

/// Waitqueue the reaper kernel task parks on. `exit` notifies after
/// queuing the victim; the reaper drains the queue on every wake.
static REAPER_WQ: WaitQueue = WaitQueue::new();

/// Install the bootstrap task wrapping the currently-running thread.
/// Must be called exactly once, before any [`spawn`].
pub fn init() {
    // Confirm the production seam wire-up is reachable before any
    // scheduler dispatch (RFC 0005 §Security A1). `env()` must hand
    // back the `HwClock` / `HwIrq` singletons. We compare the trait
    // object references directly — `core::ptr::eq` on `&dyn Trait`
    // compares both the data pointer and the vtable pointer, so two
    // ZST adapters that happened to share a data address but had
    // different impls would still fail. Casting through `*const ()`
    // would silently lose the vtable half of the identity check.
    // Vtable identity for `&dyn Trait` is per-codegen-unit, so this
    // check has to happen inside `env.rs` itself — see
    // `assert_production_env` for the gory details.
    debug_assert!(env::assert_production_env());

    let mut sched = SCHED.lock();
    assert!(sched.current.is_none(), "task::init called twice");
    sched.current = Some(Box::new(Task::bootstrap()));
    drop(sched);
    // Spawn the reaper before any other task is created. Running at
    // DEFAULT_PRIORITY is sufficient — it only wakes when a victim
    // exists, and exit latency is not on any hot path.
    spawn(reaper_loop);
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

/// Like [`spawn`] but returns the newly-assigned task ID.
/// Used by `init_process::launch` to register PID 1 with the correct ID.
pub fn spawn_and_get_id(entry: fn() -> !) -> usize {
    let task = Box::new(Task::new_with_priority(entry, DEFAULT_PRIORITY));
    let id = task.id;
    let new_prio = task.priority;
    let mut sched = SCHED.lock();
    sched.push_ready(task);
    maybe_preempt_current_for_priority(&mut sched, new_prio);
    id
}

/// Clone the current task's address space and fd table for a fork child,
/// allocate a new kernel stack, push the child onto the ready queue, and
/// return the child's task ID.
///
/// `user_rip`, `user_rflags`, `user_rsp` are the ring-3 register state
/// saved by the SYSCALL entry before invoking `syscall_dispatch`.
pub fn fork_current_task(
    user_rip: u64,
    user_rflags: u64,
    user_rsp: u64,
) -> Result<usize, crate::mem::addrspace::ForkError> {
    use alloc::sync::Arc;
    use spin::{Mutex, RwLock};

    crate::fork_trace!(
        "fork-trace: [fork_current_task enter] user_rip={:#x} user_rflags={:#x} user_rsp={:#x}",
        user_rip,
        user_rflags,
        user_rsp
    );

    // Snapshot everything needed from the current task while holding
    // SCHED, then release it before calling fork_address_space.
    crate::fork_trace!("fork-trace: [fork_current_task] → SCHED.lock() for parent snapshot");
    let (
        parent_address_space,
        parent_fd_table,
        parent_cwd,
        parent_credentials,
        parent_priority,
        parent_affinity,
        parent_fpu_ptr,
    ) = {
        let mut sched = SCHED.lock();
        crate::fork_trace!("fork-trace: [fork_current_task] SCHED locked (snapshot scope)");
        let cur = sched
            .current
            .as_mut()
            .expect("fork_current_task: no running task");
        // Flush live FPU/SSE registers into the parent's saved area before
        // the child copies from it — otherwise the snapshot only reflects
        // state as of the parent's last context switch, not what the parent
        // has actually touched since. SCHED is held across the save so a
        // timer tick can't preempt (and overwrite the area itself) between
        // the fxsave and the copy_nonoverlapping inside new_forked.
        //
        // SAFETY: fpu::init ran at arch bringup; `cur` is the running task
        // so its FpuArea is the one whose live CPU state we are capturing,
        // and holding SCHED excludes any aliasing save from context_switch.
        crate::fork_trace!("fork-trace: [fork_current_task] → fpu::save(parent)");
        unsafe {
            crate::arch::x86_64::fpu::save(&mut cur.fpu);
        }
        crate::fork_trace!("fork-trace: [fork_current_task] ← fpu::save(parent)");
        // Snapshot the parent's credentials Arc under the rwlock. POSIX
        // fork(2) gives the child the parent's credentials at fork time;
        // a concurrent setuid on the parent thread (impossible today —
        // we are single-threaded per process — but the contract holds)
        // would race the snapshot, and the Arc-snapshot pattern is what
        // makes that race benign: the child gets whichever Credential
        // was current at the instant of `read()`.
        let parent_credentials = Arc::clone(&*cur.credentials.read());
        (
            Arc::clone(&cur.address_space),
            Arc::clone(&cur.fd_table),
            cur.cwd.clone(),
            parent_credentials,
            cur.priority,
            cur.affinity,
            // SAFETY: the parent Task is the currently-running task and stays
            // alive in SCHED for the duration of this syscall. We only read
            // the FPU area during the new_forked call below.
            &*cur.fpu as *const crate::arch::x86_64::fpu::FpuArea,
        )
    };
    crate::fork_trace!("fork-trace: [fork_current_task] SCHED released");

    // CoW-clone the address space (requires AddressSpace write lock).
    crate::fork_trace!("fork-trace: [fork_current_task] → fork_address_space()");
    let child_aspace = {
        let mut tlb = crate::mem::tlb::Flusher::new_active();
        let child = parent_address_space.write().fork_address_space(&mut tlb)?;
        tlb.finish();
        child
    };
    let child_cr3 = child_aspace.page_table_frame();
    crate::fork_trace!(
        "fork-trace: [fork_current_task] ← fork_address_space() child_cr3={:#x}",
        child_cr3.start_address().as_u64()
    );
    let child_aspace = Arc::new(RwLock::new(child_aspace));

    // Clone the fd table (slot-independent, description-shared).
    crate::fork_trace!("fork-trace: [fork_current_task] → clone_for_fork(fd_table)");
    let child_fd = Arc::new(Mutex::new(parent_fd_table.lock().clone_for_fork()));
    crate::fork_trace!("fork-trace: [fork_current_task] ← clone_for_fork(fd_table)");

    // SAFETY: parent_fpu_ptr was snapshotted while SCHED was held; the
    // parent task is the currently-running task and cannot be removed while
    // we are executing in its syscall context (single-CPU kernel).
    crate::fork_trace!("fork-trace: [fork_current_task] → Task::new_forked()");
    let child = unsafe {
        Task::new_forked(
            user_rip,
            user_rflags,
            user_rsp,
            parent_priority,
            parent_affinity,
            parent_fpu_ptr,
            child_aspace,
            child_cr3,
            child_fd,
            parent_cwd,
            parent_credentials,
        )
    }?;
    let child_id = child.id;
    crate::fork_trace!(
        "fork-trace: [fork_current_task] ← Task::new_forked() child_id={}",
        child_id
    );
    let child_box = Box::new(child);
    let new_prio = child_box.priority;
    crate::fork_trace!("fork-trace: [fork_current_task] → SCHED.lock() for push_ready");
    let mut sched = SCHED.lock();
    crate::fork_trace!(
        "fork-trace: [fork_current_task] SCHED locked; push_ready child_id={} prio={}",
        child_id,
        new_prio
    );
    sched.push_ready(child_box);
    maybe_preempt_current_for_priority(&mut sched, new_prio);
    crate::fork_trace!(
        "fork-trace: [fork_current_task exit] returning child_id={}",
        child_id
    );
    Ok(child_id)
}

/// Return the `Arc<RwLock<AddressSpace>>` of the currently-running task.
/// Used by the exec() syscall to clear and reload the address space.
///
/// # Panics
/// Panics if called before `task::init`.
pub fn current_address_space() -> alloc::sync::Arc<spin::RwLock<crate::mem::addrspace::AddressSpace>>
{
    SCHED
        .lock()
        .current
        .as_ref()
        .expect("current_address_space: no running task")
        .address_space
        .clone()
}

/// Return the CR3 frame of the currently-running task.
pub fn current_cr3() -> x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>
{
    SCHED
        .lock()
        .current
        .as_ref()
        .expect("current_cr3: no running task")
        .cr3
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
    let mut sched = SCHED.lock();

    let found = apply_priority(&mut sched, id, priority);
    if found {
        // If a ready task now outranks the running one, shorten its slice
        // so the next tick swaps it out.
        preempt_if_higher_ready(&mut sched);
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

    found
}

/// Return the fd table of the currently-running task.
///
/// Briefly locks the scheduler to clone the `Arc`, then releases it.
/// Callers that need to mutate the table should lock the returned
/// `Arc<Mutex<FileDescTable>>` separately, *not* while holding any
/// other lock whose ordering places it before `SCHED`.
///
/// # Panics
/// Panics if called before [`init`].
pub fn current_fd_table() -> alloc::sync::Arc<spin::Mutex<crate::fs::FileDescTable>> {
    SCHED
        .lock()
        .current
        .as_ref()
        .expect("current_fd_table: no running task")
        .fd_table
        .clone()
}

/// Snapshot the currently-running task's `Arc<Credential>` — the
/// wait-free read path consumed by `getuid(2)` / `geteuid(2)` /
/// `getgid(2)` / `getegid(2)` and by any VFS syscall that needs the
/// caller's DAC identity.
///
/// Locks `SCHED` only long enough to reach `current`, then takes the
/// per-task credentials rwlock in read mode, clones the inner `Arc`,
/// and drops both locks before returning. A concurrent `setuid(2)`
/// writer swaps the `Arc` in place; because `Credential` is immutable
/// once constructed, the returned snapshot remains valid and race-free
/// for the lifetime of its owner (RFC 0004 §Credential model).
///
/// # Panics
/// Panics if called before [`init`] (no running task yet).
pub fn current_credentials() -> alloc::sync::Arc<crate::fs::vfs::Credential> {
    let sched = SCHED.lock();
    let cur = sched
        .current
        .as_ref()
        .expect("current_credentials: no running task");
    // Inner scope forces the `RwLockReadGuard` to drop before the
    // outer `sched` (`IrqLockGuard`) does. Without it Rust drops the
    // inline temporary after `sched` and the borrow checker rejects
    // the expression: the guard would outlive the scheduler lock it
    // was reached through.
    let snapshot = {
        let guard = cur.credentials.read();
        alloc::sync::Arc::clone(&*guard)
    };
    drop(sched);
    snapshot
}

/// Atomically replace the currently-running task's credentials with
/// `new_cred`. The write-side partner of [`current_credentials`]: the
/// caller constructs a fresh [`Credential`](crate::fs::vfs::Credential)
/// (typically by cloning the existing snapshot and overriding the
/// relevant `uid`/`gid` fields) and this helper swaps the inner `Arc`
/// under the per-task `BlockingRwLock`.
///
/// Readers that took an earlier `Arc` snapshot via
/// `current_credentials()` continue to see the pre-swap `Credential` —
/// the swap only becomes visible on the next read. Combined with
/// `Credential`'s immutability, this is the atomic `Arc`-swap model
/// documented in RFC 0004 §Credential model: a `setuid(2)` family write
/// cannot tear an in-flight VFS DAC check on a sibling thread.
///
/// Mirrors the SCHED-lock pattern used by [`current_credentials`] — we
/// take `SCHED` once, acquire the per-task credentials lock through it,
/// and drop both under a single inner scope so the lock guards release
/// in the correct order.
///
/// # Panics
/// Panics if called before [`init`] (no running task yet).
pub fn replace_current_credentials(new_cred: crate::fs::vfs::Credential) {
    let sched = SCHED.lock();
    let cur = sched
        .current
        .as_ref()
        .expect("replace_current_credentials: no running task");
    // Inner scope forces the `RwLockWriteGuard` to drop before the
    // outer `sched` (`IrqLockGuard`), same as `current_credentials`.
    {
        let mut guard = cur.credentials.write();
        *guard = alloc::sync::Arc::new(new_cred);
    }
    drop(sched);
}

/// Return the per-process current working directory dentry, or `None`
/// if no cwd has been set (bootstrap / kernel-only tasks). Callers
/// should fall back to [`crate::fs::vfs::root`] on `None`.
///
/// Briefly locks the scheduler to clone the `Arc`, then releases it.
pub fn current_cwd() -> Option<alloc::sync::Arc<crate::fs::vfs::Dentry>> {
    SCHED
        .lock()
        .current
        .as_ref()
        .and_then(|t| t.cwd.as_ref().map(|p| p.clone_arc()))
}

/// Replace the currently-running task's `Credential` snapshot.
///
/// Used by the `setuid(2)` / `setgid(2)` family once they land in
/// userspace, and by integration tests that want to exercise DAC
/// checks with a non-root credential. Builds a fresh `Arc<Credential>`
/// rather than mutating in place; existing read-side snapshots keep
/// the prior `Arc` alive and see a consistent pre-swap view.
pub fn set_current_credentials(cred: crate::fs::vfs::Credential) {
    let sched = SCHED.lock();
    if let Some(t) = sched.current.as_ref() {
        *t.credentials.write() = alloc::sync::Arc::new(cred);
    }
}

/// Set the per-process current working directory to `dentry`.
///
/// Called by `sys_chdir` after successfully resolving and verifying
/// that the target is a directory.
pub fn set_current_cwd(dentry: alloc::sync::Arc<crate::fs::vfs::Dentry>) {
    // Construct the `PinnedDentry` *before* taking the SCHED lock: the
    // old cwd's Drop may run during the replacement and calls
    // `finalize_pending_detach`, which takes the `PENDING_DETACH`
    // blocking mutex. Doing that work under SCHED would invert the
    // lock order against every other finalize path.
    let new_cwd = crate::fs::vfs::PinnedDentry::new(dentry);
    let _old = {
        let mut sched = SCHED.lock();
        sched
            .current
            .as_mut()
            .and_then(|cur| cur.cwd.replace(new_cwd))
    };
    // `_old` drops here with no locks held.
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

/// Top of the currently-running task's dedicated SYSCALL kernel stack,
/// or `0` for kernel-only tasks. Exposed primarily so the integration
/// test for [`set_active_syscall_stack`] can compare against
/// [`crate::arch::x86_64::gdt::tss_rsp0`] and confirm the two agree
/// after a context switch.
pub fn current_syscall_stack_top() -> u64 {
    SCHED
        .lock()
        .current
        .as_ref()
        .map(|t| t.syscall_stack_top)
        .unwrap_or(0)
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

/// Check whether `addr` falls within any kernel-task guard page in
/// the task-stack VA window. Returns the slot index of the overflowing
/// stack, or `None` if no guard page was hit.
///
/// Fully lock-free: derives the answer from the fixed VA layout of the
/// task stack window, so it is always safe to call from any exception
/// context — even when the scheduler lock is already held on this CPU.
///
/// The returned value is the *slot index*, not a task ID. Pre-#646
/// every slot was bump-allocated and never reused, so the slot index
/// happened to equal `task.id - 1`. With slot recycling that
/// equivalence no longer holds; callers that need a stable identifier
/// for the overflowing task must walk the live task list themselves.
pub fn find_stack_overflow(addr: usize) -> Option<usize> {
    use super::task::{GUARD_SIZE, NEXT_STACK_VA, TASK_SLOT_SIZE, TASK_STACKS_VA_BASE};
    use core::sync::atomic::Ordering;

    let next_va = NEXT_STACK_VA.load(Ordering::Relaxed);
    if addr < TASK_STACKS_VA_BASE || addr >= next_va {
        return None;
    }
    let slot_idx = (addr - TASK_STACKS_VA_BASE) / TASK_SLOT_SIZE;
    let slot_guard_base = TASK_STACKS_VA_BASE + slot_idx * TASK_SLOT_SIZE;
    // Guard page occupies [slot_guard_base, slot_guard_base + GUARD_SIZE).
    if addr < slot_guard_base + GUARD_SIZE {
        Some(slot_idx)
    } else {
        None
    }
}

/// Update the current task's saved CR3 frame to `frame`. Call this
/// before writing a new PML4 to CR3 directly so that subsequent
/// context switches (which load `task.cr3`) use the new PML4.
///
/// Must be called from task context with interrupts enabled (the
/// scheduler lock is taken briefly to mutate the current task).
pub fn update_current_cr3(
    frame: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>,
) {
    let mut sched = SCHED.lock();
    let current = sched
        .current
        .as_mut()
        .expect("update_current_cr3: no running task");
    current.cr3 = frame;
}

/// Replace the current task's address space and CR3 with a pre-built
/// `AddressSpace`. Returns the *old* `Arc` so the caller can drop it **after**
/// the CPU's CR3 has been switched away — dropping it here would free the
/// old PML4 frame while it is still the active page table root, creating a
/// use-after-free if an interrupt fires in the gap.
///
/// Called from `init_ring3_entry` to install the address space that was
/// prepared in `init_process::launch` (which includes ELF VMA entries and
/// a stack VMA so fork works correctly).
pub fn replace_current_address_space(
    aspace: alloc::sync::Arc<spin::RwLock<crate::mem::addrspace::AddressSpace>>,
    cr3: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>,
) -> alloc::sync::Arc<spin::RwLock<crate::mem::addrspace::AddressSpace>> {
    let mut sched = SCHED.lock();
    let current = sched
        .current
        .as_mut()
        .expect("replace_current_address_space: no running task");
    let old = core::mem::replace(&mut current.address_space, aspace);
    current.cr3 = cr3;
    old // caller must drop this AFTER switching CR3
}

/// Single choke point for updating the SYSCALL/IRQ kernel-entry stack
/// pointers on a context switch: writes both
/// [`crate::arch::x86_64::syscall::SYSCALL_KERNEL_RSP`] (read by the
/// `syscall_entry` trampoline on SYSCALL) and `TSS.rsp[0]` (read by the
/// CPU on ring-3 → ring-0 interrupt or exception) from
/// `task.syscall_stack_top`.
///
/// A `syscall_stack_top` of `0` means the task is kernel-only — it
/// will never execute SYSCALL from ring-3, and leaving the previous
/// task's stack pointers in place is harmless because nothing will
/// consult them until the next ring-3 task is switched in.
///
/// # Why a helper
///
/// The preempt / block / exit paths each need to perform exactly this
/// pair of writes after selecting the incoming task. Before this
/// consolidation (issue #505) the sequence was inlined at three call
/// sites — drift between them (e.g. a fourth switch path forgetting
/// the update) would silently route the incoming ring-3 task's
/// syscalls onto a previous task's kernel stack and corrupt it. Having
/// a single named helper makes "this is how a switch updates the
/// syscall stack" searchable and reviewable.
///
/// # Debug-only invariants
///
/// - When the task carries a non-zero `syscall_stack_top`, it must
///   point somewhere above the task's own kernel-stack guard page —
///   a SYSCALL entry would otherwise land on or below the guard and
///   take a #PF (or, worse, into some other task's allocation if the
///   value is entirely stale). Ring-3 arming is done once per task by
///   [`arm_ring3_syscall_stack`] while the task is `current`; every
///   subsequent switch-in passes the value through unchanged.
/// - After the pair of writes, confirm the live TSS struct and the
///   `SYSCALL_KERNEL_RSP` atomic both hold the value we just wrote.
///   This catches a lost write (e.g. a mis-aimed pointer, or a future
///   refactor that accidentally breaks the symmetry between the two
///   writes).
///
/// `IA32_KERNEL_GS_BASE` is not used by the current kernel — there is
/// no `swapgs` on the SYSCALL entry path — so the readback checks the
/// TSS struct directly against the atomic shadow and
/// `SYSCALL_KERNEL_RSP`. If a future ring-0 stack-swap mechanism
/// starts using `IA32_KERNEL_GS_BASE`, add an `rdmsr` check here.
pub(in crate::task) fn set_active_syscall_stack(task: &Task) {
    use crate::arch::x86_64::gdt::{set_tss_rsp0, tss_rsp0, tss_rsp0_shadow};
    use crate::arch::x86_64::syscall::SYSCALL_KERNEL_RSP;
    use core::sync::atomic::Ordering;

    let top = task.syscall_stack_top;

    if top == 0 {
        // Kernel-only task (or the bootstrap task before
        // `arm_ring3_syscall_stack` runs). No SYSCALL stack to arm —
        // leave the previous ring-3 task's stack pointers in place,
        // which is harmless because a kernel-only task cannot execute
        // SYSCALL. The scheduler will call this helper again when a
        // ring-3 task switches back in.
        return;
    }

    // Debug-only sanity on the source of truth: an armed ring-3 task
    // must have been set up with a top above its own guard page. A
    // ring-3 task whose `syscall_stack_top` sits inside (or below) its
    // guard would SYSCALL onto the guard and take a #PF; catch that
    // in debug rather than letting the first syscall explode.
    debug_assert!(
        task.guard_base == 0 || top as usize > task.guard_base,
        "set_active_syscall_stack: task id={} syscall_stack_top ({:#x}) not above guard_base ({:#x})",
        task.id,
        top,
        task.guard_base,
    );

    SYSCALL_KERNEL_RSP.store(top, Ordering::Relaxed);
    set_tss_rsp0(top);

    if cfg!(debug_assertions) {
        let shadow = tss_rsp0_shadow();
        let live = tss_rsp0();
        let syscall_rsp = SYSCALL_KERNEL_RSP.load(Ordering::Relaxed);
        debug_assert_eq!(
            shadow, top,
            "set_active_syscall_stack: TSS_RSP0 atomic shadow ({shadow:#x}) != helper write ({top:#x})",
        );
        debug_assert_eq!(
            live, top,
            "set_active_syscall_stack: live TSS.rsp[0] ({live:#x}) != helper write ({top:#x})",
        );
        debug_assert_eq!(
            syscall_rsp, top,
            "set_active_syscall_stack: SYSCALL_KERNEL_RSP ({syscall_rsp:#x}) != helper write ({top:#x})",
        );
    }
}

/// Prepare the current task to run in ring-3: configure TSS.rsp[0] and
/// `SYSCALL_KERNEL_RSP` to point at the TOP of this task's own kernel stack
/// so ring-3 syscalls and exceptions land on a per-task stack (not the shared
/// `INIT_KERNEL_STACK`). Also records `syscall_stack_top` in the task so
/// the preempt/block paths can restore it when context-switching back here.
///
/// Must be called from the task's kernel entry function (e.g.
/// `init_ring3_entry`) *before* jumping to ring-3 with `jump_to_ring3`.
pub fn arm_ring3_syscall_stack() {
    // GUARD_SIZE=4096 and STACK_SIZE=16*1024 from task.rs (private constants;
    // replicated here to avoid visibility issues — must stay in sync with task.rs).
    const GUARD_SIZE: usize = 4096;
    const STACK_SIZE: usize = 16 * 1024;

    let mut sched = SCHED.lock();
    let current = sched
        .current
        .as_mut()
        .expect("arm_ring3_syscall_stack: no running task");
    let top = (current.guard_base + GUARD_SIZE + STACK_SIZE) as u64;
    current.syscall_stack_top = top;
    // Delegate to the single choke point so the switch-path helpers
    // and the initial-arming path use exactly the same update sequence.
    set_active_syscall_stack(current);
}

/// Install a VMA on the currently-running task. The VMA is resolved
/// lazily by the `#PF` handler on first touch of each page via
/// [`VmObject::fault`].
pub fn install_vma_on_current(vma: crate::mem::vmatree::Vma) {
    let aspace = {
        let sched = SCHED.lock();
        let current = sched
            .current
            .as_ref()
            .expect("install_vma_on_current: no running task");
        current.address_space.clone()
    };
    aspace.write().insert(vma);
}

/// Consult the current task's address space for `addr`. Returns the
/// VMA's backing object, the page-aligned byte offset into that object,
/// the cached PTE flags, and the sharing discipline.
///
/// Returns `None` if the scheduler lock is contended — the `#PF`
/// handler treats that as "not a demand-page fault" and falls through
/// to the generic hang path. In practice contention only arises when
/// the fault hit mid-`context_switch`; for demand-paged tasks running
/// normally the lock is free at fault time.
pub fn current_vma_lookup(
    addr: usize,
) -> Option<(
    alloc::sync::Arc<dyn crate::mem::vmobject::VmObject>,
    usize,
    crate::mem::vmatree::ProtPte,
    crate::mem::vmatree::Share,
)> {
    let aspace = {
        let sched = SCHED.try_lock()?;
        let current = sched.current.as_ref()?;
        current.address_space.clone()
    };
    // Take the write lock even for a read: the resolver in `idt.rs`
    // mutates page-table state under this guarantee, and once SMP and
    // CoW refcount fast-paths land we need exclusive access to the
    // address space across the whole fault to keep the rc==1 check
    // race-free. `try_write` keeps the existing "contention → not a
    // demand fault" contract.
    let guard = aspace.try_write()?;
    let vma = guard.find(addr)?;
    let page_aligned = addr & !(4096 - 1);
    let offset = page_aligned - vma.start + vma.object_offset;
    Some((
        alloc::sync::Arc::clone(&vma.object),
        offset,
        vma.prot_pte,
        vma.share,
    ))
}

/// Try to resolve a growsdown stack fault at `addr`. Called from the
/// `#PF` handler when `current_vma_lookup` returns `None` (address
/// is below the current VMA start of a growsdown VMA). On success,
/// extends the VMA one page downward and returns the object/offset/prot
/// needed to install the demand-page PTE. Returns `None` on contention
/// or if the fault is not a valid growsdown extension.
pub fn current_growsdown_lookup(
    addr: usize,
) -> Option<(
    alloc::sync::Arc<dyn crate::mem::vmobject::VmObject>,
    usize,
    crate::mem::vmatree::ProtPte,
    usize, // new_vma_start: the page address the VMA was installed at
)> {
    let aspace = {
        let sched = SCHED.try_lock()?;
        let current = sched.current.as_ref()?;
        current.address_space.clone()
    };
    let mut guard = aspace.try_write()?;
    guard.grow_stack(addr)
}

/// Terminate the currently-running task. Reclaims the task's mapped
/// stack pages, VMA-backed frames, and PML4 frame in the reaper kernel
/// task (spawned by [`init`]), then drops the `Box<Task>`.
///
/// The actual reclaim runs from [`reaper_loop`] in task context rather
/// than inline here because it unmaps the very stack we're executing
/// on — we have to context-switch away first — and because the
/// reclaim path takes `BlockingMutex` locks (kernel frame allocator,
/// HHDM mapping state) which would deadlock if held from the timer
/// ISR. The exiting task is queued in [`REAPER_VICTIMS`] and the
/// reaper is notified before we context-switch away.
///
/// The stack VA slot (`NEXT_STACK_VA`'s bump-allocated range) is
/// returned to the slot free-list via [`task::free_stack_slot`] so a
/// subsequent fork can recycle it (#646). Without this, every
/// fork+exec+wait cycle permanently consumed a 20 KiB slot and
/// long-running soak runs eventually exhausted the arena.
///
/// # Panics
/// - No other ready task exists (exiting the last runnable task would
///   halt the kernel).
/// - The bootstrap task calls `exit` — it owns the kernel PML4 and the
///   inherited boot stack, neither of which the reaper may reclaim.
pub fn exit() -> ! {
    // Disable IRQs before acquiring SCHED so that IrqLock saves `false`
    // and restores `false` on guard drop — keeping IRQs masked through
    // the context_switch call below, which executes after the guard is
    // released. IrqLock cannot be used end-to-end here because the
    // guard drop would re-enable IRQs before context_switch.
    interrupts::disable();
    let (prev_rsp_ptr, next_rsp, next_cr3, next_fpu_ptr) = {
        let mut sched = SCHED.lock();
        // Exiting the bootstrap task would reap the kernel PML4 and
        // the inherited boot stack — neither of which we own. Reject
        // it up-front rather than relying on per-field guards deeper
        // in the reaper.
        assert!(
            sched
                .current
                .as_ref()
                .expect("task::exit before task::init")
                .id
                != 0,
            "task::exit: bootstrap task may not exit"
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
        // Arm SYSCALL/TSS for the incoming task's own per-task kernel
        // stack. Done while still holding SCHED so the Task reference
        // outlives the write.
        set_active_syscall_stack(sched.current.as_ref().unwrap());
        let next_fpu_ptr: *const fpu::FpuArea = &*sched.current.as_ref().unwrap().fpu;
        // Enqueue the doomed task for the reaper task to drain in its
        // own context. We drop SCHED before touching REAPER_VICTIMS /
        // REAPER_WQ to keep the lock order SCHED -> REAPER_VICTIMS and
        // SCHED -> WaitQueue.inner consistent with the rest of the
        // task module.
        let mut victims = REAPER_VICTIMS.lock();
        victims.push_back(prev);
        let prev_ref = victims.back_mut().unwrap();
        // SAFETY: `prev_ref` is a stable `Box<Task>` in the queue tail.
        // We only push_back and the reaper only drains by taking the
        // whole queue — the heap location remains valid through this
        // `context_switch`'s single write to `prev.rsp`.
        let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;
        drop(victims);
        (prev_rsp_ptr, next_rsp, next_cr3, next_fpu_ptr)
    };
    // Poke the reaper before we switch away. `notify_all` takes
    // `WaitQueue.inner` then `SCHED` (via `task::wake`); SCHED was
    // already dropped above, so this is safe.
    REAPER_WQ.notify_all();
    // SAFETY: IRQs are masked, SCHED is dropped, prev_rsp_ptr targets
    // a stable heap location, next_cr3 is a valid per-task PML4,
    // next_fpu_ptr points into a Box<FpuArea> pinned by the scheduler.
    // We intentionally skip `fpu::save` — the exiting task is doomed.
    unsafe {
        fpu::restore(&*next_fpu_ptr);
        context_switch(prev_rsp_ptr, next_rsp, next_cr3);
    }
    unreachable!("task::exit returned from context_switch");
}

/// Reclaim the stack pages of a task that called [`exit`], then drop
/// the `Box<Task>`. Called from [`reaper_loop`] on a stack that is
/// *not* the victim's — the victim already context-switched away, so
/// unmapping its stack is safe.
///
/// VMA-backed leaf frames, intermediate page tables, and the PML4 are
/// reclaimed by `Drop for AddressSpace`, which fires when the last
/// `Arc<RwLock<AddressSpace>>` is released as the `Box<Task>` is
/// dropped at the end of this function (#161).
fn reap_pending(victim: alloc::boxed::Box<Task>) {
    use crate::mem::paging;
    use x86_64::structures::paging::{Page, Size4KiB};
    use x86_64::VirtAddr;

    // Unmap + free stack pages. Stack pages live in the shared
    // upper-half kernel window (L4 entry 416) — the L3 subtree under
    // that entry is aliased into every per-task PML4, so unmapping via
    // the victim's PML4 propagates to every PML4.
    //
    // We route through `unmap_and_free_in_pml4` (temporary mapper)
    // rather than `unmap_and_free` (global `MAPPER` lock) so the
    // reaper can reclaim a victim whose last pre-exit state left it
    // holding `MAPPER`. Even though the reaper now runs in task
    // context with IRQs enabled (and so could legally park), staying
    // on the temporary-mapper path keeps this routine deadlock-free
    // regardless of what locks the victim happened to be holding.
    let stack_base = victim.stack_base();
    if stack_base != 0 {
        let mut all_unmapped = true;
        for i in 0..victim.stack_page_count() {
            let va = stack_base + i * 4096;
            let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64))
                .expect("stack page VA aligned by construction");
            if let Err(e) = paging::unmap_and_free_in_pml4(victim.cr3, page) {
                serial_println!(
                    "tasks: reap task {} unmap stack page {:#x} failed: {:?} — \
                     leaking VA slot {:#x}..{:#x} to avoid stale-PTE recycle",
                    victim.id,
                    va,
                    e,
                    victim.guard_base,
                    victim.guard_base + super::task::TASK_SLOT_SIZE
                );
                all_unmapped = false;
            }
        }

        if all_unmapped {
            // Return the now-fully-unmapped stack VA slot to the free list
            // so a subsequent fork can recycle it (#646). The guard page
            // was never mapped; the loop above has just released every
            // mapped stack page via `unmap_and_free_in_pml4`. If any unmap
            // failed we deliberately leak the slot — recycling a slot with
            // stale upper-half PTEs would resurrect exactly the class of
            // bug this PR fixes.
            super::task::free_stack_slot(victim.guard_base);
            serial_println!(
                "tasks: reaped task {} (stack VA slot {:#x}..{:#x} returned)",
                victim.id,
                victim.guard_base,
                victim.guard_base + super::task::TASK_SLOT_SIZE
            );
        }
    }

    // Drop the Box<Task>. The Arc<RwLock<AddressSpace>> goes with it;
    // when the strong count reaches zero, `Drop for AddressSpace`
    // walks the VMAs, frees every leaf frame (detecting and freeing
    // private CoW copies via VmObject::frame_at), frees the user-half
    // intermediate page tables, and frees the PML4 itself.
    drop(victim);
}

/// The reaper kernel task. Parks on [`REAPER_WQ`] until [`exit`]
/// queues a victim, then drains the whole queue and reclaims each
/// task's resources via [`reap_pending`].
///
/// Running the reclaim path here — in task context, IRQs enabled —
/// instead of in `preempt_tick` means we can safely take the
/// `BlockingMutex`-protected kernel frame allocator and the HHDM
/// mapping state. The previous ISR-based path would deadlock if the
/// timer fired while another task held either lock.
///
/// Takes the whole queue in a single `mem::take` so the reaper's
/// reclaim loop runs with no lock held, allowing further `exit`s to
/// enqueue against `REAPER_VICTIMS` concurrently.
fn reaper_loop() -> ! {
    loop {
        REAPER_WQ.wait_while(|| REAPER_VICTIMS.lock().is_empty());
        let drained: VecDeque<Box<Task>> = core::mem::take(&mut *REAPER_VICTIMS.lock());
        for victim in drained {
            reap_pending(victim);
        }
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
    // Drain any pending soft-IRQs before touching the scheduler lock.
    // Handlers run IRQ-off on the interrupted task's stack; keeping
    // them outside the SCHED critical section means a handler that
    // wakes a task doesn't deadlock on our own lock.
    softirq::drain();

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

    // Drain any tick-deadline wakeups (see `task::sleep_ms`) and
    // promote their targets. Runs before the preemption decision so a
    // freshly-unparked task is visible in the highest-ready check.
    //
    // Routed through `env()` (RFC 0005) so the host-side simulator and
    // mock tests can substitute their own clock. Production resolves
    // to `HwClock` over `crate::time::*` — pure forwarding, no added
    // synchronization (see `env::HwClock`).
    let (clock, _irq) = env::env();
    let now = clock.now();
    for id in clock.drain_expired(now) {
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
    // Arm SYSCALL/TSS for the incoming task's own per-task kernel
    // stack. Done while still holding SCHED so the Task reference is
    // valid; the helper only performs atomic / live-TSS writes and
    // does not take any other lock.
    set_active_syscall_stack(sched.current.as_ref().unwrap());
    // Grab a raw pointer to the incoming task's FPU area while we
    // still hold the mutable borrow; we'll dereference it after the
    // lock is dropped.
    let next_fpu_ptr: *const fpu::FpuArea = &*sched.current.as_ref().unwrap().fpu;
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
    let prev_fpu_ptr: *mut fpu::FpuArea = &mut *prev_ref.fpu;
    drop(sched);

    // SAFETY: `prev_rsp_ptr` / `prev_fpu_ptr` / `next_fpu_ptr` point
    // into heap-allocated `FpuArea` / `usize` fields behind Box<Task>
    // values in the scheduler — the Box indirection pins those
    // allocations across VecDeque or BTreeMap rebalances (rebalancing
    // moves the Box, not the heap-allocated Task). IRQs are already
    // masked inside the ISR, so no other scheduler path can race us
    // between lock drop and the context switch. `next_cr3` is a valid
    // PML4 whose upper half mirrors the kernel PML4 (by construction
    // in `Task::new` / `Task::bootstrap`). `fpu::init()` ran during
    // `arch::init`, so fxsave64/fxrstor64 are legal on this CPU.
    unsafe {
        fpu::save(&mut *prev_fpu_ptr);
        fpu::restore(&*next_fpu_ptr);
        // Note: SYSCALL/TSS stack pointers were armed above under the
        // SCHED lock via `set_active_syscall_stack`; see the helper for
        // why this consolidation exists (#505).
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
    // Disable IRQs before acquiring SCHED so that IrqLock saves `false`
    // and restores `false` on guard drop — keeping IRQs masked through
    // the context_switch call below, which executes after the guard is
    // released. IrqLock cannot be used end-to-end here because the guard
    // drop would re-enable IRQs before context_switch. `was_on` is saved
    // before the disable so IF can be restored correctly after the switch.
    let was_on = interrupts::are_enabled();
    interrupts::disable();

    let (prev_rsp_ptr, prev_fpu_ptr, next_fpu_ptr, next_rsp, next_cr3) = {
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
        // Arm SYSCALL/TSS for the incoming task's own per-task kernel
        // stack under the SCHED lock; see `set_active_syscall_stack`
        // for why this consolidation exists (#505).
        set_active_syscall_stack(sched.current.as_ref().unwrap());
        let next_fpu_ptr: *const fpu::FpuArea = &*sched.current.as_ref().unwrap().fpu;
        sched.parked.insert(prev_id, prev);

        let prev_ref = sched
            .parked
            .get_mut(&prev_id)
            .expect("just inserted into parked");
        // SAFETY: `prev_ref` is `&mut Box<Task>`; the Box heap-allocates
        // the Task, so `&mut prev_ref.rsp` / `&mut *prev_ref.fpu` point
        // at stable memory that survives any BTreeMap rebalance
        // (rebalancing moves the Box, not the heap-allocated Task it
        // points at). Same invariant as preempt_tick's ready-queue push.
        let prev_rsp_ptr: *mut usize = &mut prev_ref.rsp as *mut usize;
        let prev_fpu_ptr: *mut fpu::FpuArea = &mut *prev_ref.fpu;

        (prev_rsp_ptr, prev_fpu_ptr, next_fpu_ptr, next_rsp, next_cr3)
    };

    // SAFETY: IRQs are masked, the SCHED lock is dropped so the
    // incoming task can re-enter the scheduler, and prev_rsp_ptr /
    // prev_fpu_ptr / next_fpu_ptr target stable heap memory (see the
    // insert comment above). `next_cr3` is a valid per-task PML4 (see
    // preempt_tick). `fpu::init()` ran during `arch::init`.
    unsafe {
        fpu::save(&mut *prev_fpu_ptr);
        fpu::restore(&*next_fpu_ptr);
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
    let mut sched = SCHED.lock();
    wake_in_sched(&mut sched, id);
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
    // Routed through `env()` (RFC 0005) so simulator/mock builds can
    // drive sleeps deterministically. Production resolves to
    // `HwClock` — semantically identical to the previous direct
    // `time::ticks` / `time::enqueue_wakeup` pair.
    let (clock, _irq) = env::env();
    let ticks_to_wait = ms.div_ceil(crate::time::TICK_MS).max(1);
    let deadline = clock.now().saturating_add(ticks_to_wait);
    let id = current_id();
    clock.enqueue_wakeup(deadline, id);
    block_current();
}
