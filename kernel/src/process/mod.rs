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
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU32 as ExitEvent, Ordering};

use spin::{Lazy, Mutex};

use crate::signal::SignalState;
use crate::sync::WaitQueue;
use crate::tty::{ProcessGroupId, SessionId, Tty};

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
    /// Per-process signal state — pending mask, blocked mask, dispositions.
    pub signals: Arc<Mutex<SignalState>>,
    /// POSIX session id. `setsid` creates a new session with `session_id
    /// == pgrp_id == pid`; children inherit across `fork` and `execve`.
    pub session_id: SessionId,
    /// POSIX process-group id. Always equal to the pgrp leader's pid.
    pub pgrp_id: ProcessGroupId,
    /// Controlling terminal, if any. Cleared by `setsid`; `TIOCSCTTY`
    /// (#376) acquires one; shared by every member of a session via
    /// `Arc` so the tty outlives the session leader until every
    /// referring process has dropped it.
    pub controlling_tty: Option<Arc<Tty>>,
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
            signals: Arc::new(Mutex::new(SignalState::new())),
            session_id: 1,
            pgrp_id: 1,
            controlling_tty: None,
        },
    );
    t.pid_of.insert(task_id, 1);
}

/// Allocate a new PID and insert a live entry for `task_id` with
/// `parent_pid` as parent, inheriting session / pgrp / controlling tty
/// from the parent entry. Returns the new PID.
///
/// If `parent_pid` is not in the table (kernel-origin process, test
/// harness), the new entry starts with `session_id == pgrp_id == pid`
/// and no controlling tty — i.e. its own session.
pub fn register(task_id: usize, parent_pid: u32) -> u32 {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let mut t = TABLE.lock();
    let (session_id, pgrp_id, controlling_tty) = t
        .by_pid
        .get(&parent_pid)
        .map(|p| (p.session_id, p.pgrp_id, p.controlling_tty.clone()))
        .unwrap_or((pid, pid, None));
    t.by_pid.insert(
        pid,
        ProcessEntry {
            pid,
            task_id,
            parent_pid,
            exit_status: None,
            state: ProcessState::Alive,
            signals: Arc::new(Mutex::new(SignalState::new())),
            session_id,
            pgrp_id,
            controlling_tty,
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

// ── Signal helpers ────────────────────────────────────────────────────────

/// Look up the `SignalState` for the process that owns `task_id` and call
/// `f` with a mutable reference to it.  Returns `None` if no process entry
/// exists for the task.
///
/// TABLE is released before `f` is called (the `Arc<Mutex<SignalState>>` is
/// cloned out while TABLE is held, then locked independently).  `f` must not
/// call any function that tries to take the signal `Mutex` a second time on
/// the same task (re-entrancy).
pub fn with_signal_state_for_task<R>(
    task_id: usize,
    f: impl FnOnce(&mut SignalState) -> R,
) -> Option<R> {
    let signals = {
        let t = TABLE.lock();
        let pid = *t.pid_of.get(&task_id)?;
        let entry = t.by_pid.get(&pid)?;
        Arc::clone(&entry.signals)
    }; // TABLE released here
    let x = Some(f(&mut signals.lock()));
    x
}

/// Return the scheduler task ID for `pid`, or `None` if not found.
pub fn task_id_for_pid(pid: u32) -> Option<usize> {
    let t = TABLE.lock();
    t.by_pid.get(&pid).map(|e| e.task_id)
}

// ── Session / process-group syscalls ──────────────────────────────────────
//
// POSIX errno values returned by these helpers. Centralised so the syscall
// dispatch arms stay readable.
const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINVAL: i64 = -22;

/// Pure helper behind `setsid()` — see [`sys_setsid`]. Accepts the caller
/// pid explicitly so host unit tests can drive it without going through
/// the scheduler's `current_id()`.
pub fn setsid_for(caller_pid: u32) -> i64 {
    if caller_pid == 0 {
        return EPERM;
    }
    let mut t = TABLE.lock();
    let Some(entry) = t.by_pid.get_mut(&caller_pid) else {
        return EPERM;
    };
    if entry.pgrp_id == caller_pid {
        return EPERM;
    }
    entry.session_id = caller_pid;
    entry.pgrp_id = caller_pid;
    entry.controlling_tty = None;
    caller_pid as i64
}

/// `setsid()` — create a new session with the caller as leader.
///
/// POSIX requires EPERM if the caller is already a process-group leader,
/// to prevent a pgrp being split across two sessions.  On success sets
/// `session_id == pgrp_id == pid` and drops any existing controlling tty,
/// then returns the new session id.
pub fn sys_setsid() -> i64 {
    setsid_for(current_pid())
}

/// `getsid(pid)` — return the session id of `pid`, or of the caller if
/// `pid == 0`. Returns ESRCH for unknown pids.
pub fn sys_getsid(pid: u32) -> i64 {
    let t = TABLE.lock();
    let target = if pid == 0 {
        let self_pid = *t.pid_of.get(&crate::task::current_id()).unwrap_or(&0);
        if self_pid == 0 {
            return ESRCH;
        }
        self_pid
    } else {
        pid
    };
    match t.by_pid.get(&target) {
        Some(e) => e.session_id as i64,
        None => ESRCH,
    }
}

/// `getpgid(pid)` — return the pgrp id of `pid`, or of the caller if
/// `pid == 0`. Returns ESRCH for unknown pids.
pub fn sys_getpgid(pid: u32) -> i64 {
    let t = TABLE.lock();
    let target = if pid == 0 {
        let self_pid = *t.pid_of.get(&crate::task::current_id()).unwrap_or(&0);
        if self_pid == 0 {
            return ESRCH;
        }
        self_pid
    } else {
        pid
    };
    match t.by_pid.get(&target) {
        Some(e) => e.pgrp_id as i64,
        None => ESRCH,
    }
}

/// Pure helper behind `setpgid()` — see [`sys_setpgid`]. Accepts the
/// caller pid explicitly for testability.
pub fn setpgid_for(caller_pid: u32, pid: u32, pgid: u32) -> i64 {
    if caller_pid == 0 {
        return EPERM;
    }
    let mut t = TABLE.lock();

    let target_pid = if pid == 0 { caller_pid } else { pid };
    let pgid = if pgid == 0 { target_pid } else { pgid };

    let caller_session = match t.by_pid.get(&caller_pid) {
        Some(e) => e.session_id,
        None => return EPERM,
    };

    let (target_session, target_is_leader) = match t.by_pid.get(&target_pid) {
        Some(e) => (e.session_id, e.session_id == e.pid),
        None => return ESRCH,
    };

    if target_pid != caller_pid {
        let parent_is_caller = t
            .by_pid
            .get(&target_pid)
            .map(|e| e.parent_pid == caller_pid)
            .unwrap_or(false);
        if !parent_is_caller {
            return ESRCH;
        }
    }

    if target_session != caller_session {
        return EPERM;
    }

    if target_is_leader {
        return EPERM;
    }

    if pgid != target_pid {
        match t.by_pid.values().find(|e| e.pgrp_id == pgid) {
            Some(e) if e.session_id == caller_session => {}
            Some(_) => return EPERM,
            None => return EINVAL,
        }
    }

    if let Some(entry) = t.by_pid.get_mut(&target_pid) {
        entry.pgrp_id = pgid;
    }
    0
}

/// `setpgid(pid, pgid)` — move `pid` into process group `pgid`.
///
/// Per POSIX:
/// - `pid == 0` means the caller; `pgid == 0` means "same as `pid`".
/// - The target must be the caller or one of the caller's children.
/// - Target and `pgid`'s session must match the caller's session.
/// - `pgid` must either equal `pid` (creating a new pgrp) or name an
///   existing pgrp in the same session.
/// - A session leader may not change its own pgrp (EPERM).
pub fn sys_setpgid(pid: u32, pgid: u32) -> i64 {
    setpgid_for(current_pid(), pid, pgid)
}

/// Session/pgrp test helpers, exposed so the `session_syscalls` kernel
/// integration test can drive the table without the scheduler. Not
/// gated on `cfg(test)` because the integration test is a separate
/// crate that imports `vibix` as a normal dependency.
#[doc(hidden)]
pub mod test_helpers {
    use super::*;

    /// Drop every entry in TABLE so tests don't leak state into each
    /// other.  Also resets `NEXT_PID` so pid allocation is deterministic.
    pub fn reset_table() {
        let mut t = TABLE.lock();
        t.by_pid.clear();
        t.pid_of.clear();
        NEXT_PID.store(2, Ordering::Relaxed);
    }

    /// Insert a synthetic entry with an explicit pid so tests can drive
    /// the session syscalls without going through the real scheduler.
    pub fn insert(pid: u32, parent_pid: u32, session_id: u32, pgrp_id: u32) {
        let mut t = TABLE.lock();
        t.by_pid.insert(
            pid,
            ProcessEntry {
                pid,
                task_id: pid as usize,
                parent_pid,
                exit_status: None,
                state: ProcessState::Alive,
                signals: Arc::new(Mutex::new(SignalState::new())),
                session_id,
                pgrp_id,
                controlling_tty: None,
            },
        );
        t.pid_of.insert(pid as usize, pid);
    }

    /// Overwrite fields on an existing entry from a test — used to set
    /// up edge cases like "child is itself a session leader".
    pub fn patch(pid: u32, mut f: impl FnMut(&mut ProcessEntry)) {
        let mut t = TABLE.lock();
        if let Some(e) = t.by_pid.get_mut(&pid) {
            f(e);
        }
    }

    /// Borrow a snapshot of the entry for assertions.
    pub fn snapshot(pid: u32) -> Option<(u32, u32, bool)> {
        let t = TABLE.lock();
        t.by_pid
            .get(&pid)
            .map(|e| (e.session_id, e.pgrp_id, e.controlling_tty.is_some()))
    }

    /// Attach a fresh controlling TTY (used by setsid-clears-ctty test).
    pub fn attach_ctty(pid: u32) {
        let mut t = TABLE.lock();
        if let Some(e) = t.by_pid.get_mut(&pid) {
            e.controlling_tty = Some(Arc::new(Tty::new()));
        }
    }

    pub const EPERM_I64: i64 = EPERM;
    pub const ESRCH_I64: i64 = ESRCH;
    pub const EINVAL_I64: i64 = EINVAL;
}
