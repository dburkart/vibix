//! Kernel process table — PID allocation, parent/child tracking, and the
//! wait/exit rendezvous. One `ProcessEntry` exists per live or zombie user
//! process; the table maps `pid → entry` and `task_id → pid`.
//!
//! ## Lock ordering
//!
//! `TABLE` → `SCHED` (task module) is forbidden. `TABLE` is always released
//! before calling any function that may take `SCHED`. In practice the only
//! cross-lock path is `mark_zombie` → `CHILD_WAIT.notify_all()` →
//! `task::wake(id)` → `SCHED`, which is safe because `TABLE` is dropped
//! before the notify call.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU32 as ExitEvent, Ordering};

use spin::{Lazy, Mutex};

use crate::sync::WaitQueue;

/// Scheduling / lifecycle state of a process entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessState {
    Alive,
    /// Exit status recorded; waiting to be reaped by the parent.
    Zombie,
}

/// One entry in the process table.
pub struct ProcessEntry {
    /// This process's PID.
    pub pid: u32,
    /// Scheduler task ID for the thread of execution.
    pub task_id: usize,
    /// PID of the parent that spawned this process. `0` = kernel.
    pub parent_pid: u32,
    /// Recorded exit status (meaningful only when `state == Zombie`).
    pub exit_status: Option<i32>,
    /// Whether the process is still alive or waiting to be reaped.
    pub state: ProcessState,
}

struct Table {
    by_pid: BTreeMap<u32, ProcessEntry>,
    /// Reverse map: scheduler task id → pid.
    pid_of: BTreeMap<usize, u32>,
}

impl Table {
    const fn new() -> Self {
        Self {
            by_pid: BTreeMap::new(),
            pid_of: BTreeMap::new(),
        }
    }
}

/// Monotonic PID allocator. PID 1 is assigned explicitly by
/// `register_init`; subsequent processes start at 2.
static NEXT_PID: AtomicU32 = AtomicU32::new(2);

/// Incremented each time any process transitions to Zombie. Used by
/// `waitpid` to wait without holding TABLE lock inside WaitQueue.
static EXIT_EVENT: ExitEvent = AtomicU32::new(0);

/// All wait()-ing parents sleep on this queue until a child exits.
pub static CHILD_WAIT: Lazy<WaitQueue> = Lazy::new(WaitQueue::new);

static TABLE: Lazy<Mutex<Table>> = Lazy::new(|| Mutex::new(Table::new()));

// --- public API ---

/// Register PID 1 (the init process) with a specific task id.
/// Must be called exactly once, before any `fork()`.
pub fn register_init(task_id: usize) {
    let mut t = TABLE.lock();
    t.by_pid.insert(
        1,
        ProcessEntry {
            pid: 1,
            task_id,
            parent_pid: 0,
            exit_status: None,
            state: ProcessState::Alive,
        },
    );
    t.pid_of.insert(task_id, 1);
}

/// Allocate a new PID and insert a live entry for `task_id` with
/// `parent_pid` as parent. Returns the new PID.
pub fn register(task_id: usize, parent_pid: u32) -> u32 {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let mut t = TABLE.lock();
    t.by_pid.insert(
        pid,
        ProcessEntry {
            pid,
            task_id,
            parent_pid,
            exit_status: None,
            state: ProcessState::Alive,
        },
    );
    t.pid_of.insert(task_id, pid);
    pid
}

/// Return the PID of the currently-running task, or `0` if the running
/// task has no process table entry (e.g. the bootstrap kernel task).
pub fn current_pid() -> u32 {
    let task_id = crate::task::current_id();
    TABLE.lock().pid_of.get(&task_id).copied().unwrap_or(0)
}

/// Mark `pid` as a zombie with `exit_status`, then wake any parents
/// sleeping in `waitpid`. TABLE is released before notify to satisfy
/// the lock-ordering rule described in the module docs.
pub fn mark_zombie(pid: u32, status: i32) {
    {
        let mut t = TABLE.lock();
        if let Some(entry) = t.by_pid.get_mut(&pid) {
            entry.state = ProcessState::Zombie;
            entry.exit_status = Some(status);
        }
    }
    // Bump the event counter so wait_while predicates can check it
    // atomically without taking TABLE.
    EXIT_EVENT.fetch_add(1, Ordering::Release);
    CHILD_WAIT.notify_all();
}

/// Return the current value of the exit-event counter. `waitpid` uses
/// this to detect new zombie children without taking TABLE inside the
/// WaitQueue predicate (which would invert the TABLE → WaitQueue order).
pub fn exit_event_count() -> u32 {
    EXIT_EVENT.load(Ordering::Acquire)
}

/// Try to reap one zombie child of `parent_pid`. If `target_pid >= 0`,
/// only that specific child is considered; pass `-1` to reap any child.
///
/// Returns `Some((child_pid, exit_status))` on success, `None` if no
/// matching zombie child exists.
pub fn reap_child(parent_pid: u32, target_pid: i32) -> Option<(u32, i32)> {
    let mut t = TABLE.lock();
    let zombie_pid = t
        .by_pid
        .values()
        .find(|e| {
            e.parent_pid == parent_pid
                && e.state == ProcessState::Zombie
                && (target_pid < 0 || e.pid == target_pid as u32)
        })
        .map(|e| e.pid);

    zombie_pid.map(|pid| {
        let entry = t.by_pid.remove(&pid).unwrap();
        // Remove the reverse task_id → pid mapping for the zombie.
        t.pid_of.retain(|_, &mut p| p != pid);
        (pid, entry.exit_status.unwrap_or(0))
    })
}

/// Returns `true` if `parent_pid` has at least one child (alive or
/// zombie) in the process table.
pub fn has_children(parent_pid: u32) -> bool {
    TABLE
        .lock()
        .by_pid
        .values()
        .any(|e| e.parent_pid == parent_pid)
}

/// Reparent all children of `dead_pid` to PID 1 so they are not left
/// orphaned. Called by the `exit()` syscall before marking the process
/// as a zombie.
pub fn reparent_children(dead_pid: u32) {
    let mut t = TABLE.lock();
    for entry in t.by_pid.values_mut() {
        if entry.parent_pid == dead_pid {
            entry.parent_pid = 1;
        }
    }
}

/// Update the task_id stored for `pid` (needed after exec() replaces
/// the task identity under the same PID).
#[allow(dead_code)]
pub fn update_task_id(pid: u32, new_task_id: usize) {
    let mut t = TABLE.lock();
    // Remove stale reverse entry.
    if let Some(entry) = t.by_pid.get(&pid) {
        let old = entry.task_id;
        t.pid_of.remove(&old);
    }
    if let Some(entry) = t.by_pid.get_mut(&pid) {
        entry.task_id = new_task_id;
    }
    t.pid_of.insert(new_task_id, pid);
}
