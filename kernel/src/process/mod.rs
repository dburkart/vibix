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
//!
//! The session/pgrp syscalls (`sys_getsid`, `sys_getpgid`) sample
//! `task::current_id()` **before** taking `TABLE` so the forbidden order
//! is mechanically impossible — see #478 diagnostic
//! (https://github.com/dburkart/vibix/pull/595#issuecomment-4302346400).
//!
//! ## IF-discipline (#647)
//!
//! [`current_pid`] must be called with interrupts enabled. It spins on
//! a plain `spin::Mutex`; with `IF=0` a stuck holder cannot be
//! preempted and the kernel wedges (the failure shape traced to #478).
//! Debug builds assert `RFLAGS.IF=1` on entry and panic if the soak
//! threshold is reached. Callers in interrupt-disabled regions must
//! cache the pid before disabling IRQs.

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
///
/// Memory-ordering contract (relied on by `wait4`'s snapshot-predicate
/// loop — see `kernel/src/arch/x86_64/syscall.rs` WAIT4, and the full
/// proof for issue #508):
/// - Writer (`mark_zombie`): `fetch_add(1, Release)` *before*
///   `CHILD_WAIT.notify_all()`.
/// - Reader (`exit_event_count`): `load(Acquire)`.
///
/// A `wait4` caller that snapshots the counter, calls `reap_child` and
/// sees `None`, then re-checks under `wait_while` is guaranteed to
/// observe any concurrent exit that sequenced its Release-bump before
/// the reader's Acquire-load — either as a non-matching snapshot
/// (wait_while returns immediately) or as a queued wake.
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
    crate::fork_trace!(
        "fork-trace: [process::register enter] task_id={} parent_pid={}",
        task_id,
        parent_pid
    );
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    crate::fork_trace!(
        "fork-trace: [process::register] allocated pid={} → TABLE.lock()",
        pid
    );
    let mut t = lock_table_with_soak_check("register");
    crate::fork_trace!("fork-trace: [process::register] TABLE locked");
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
    crate::fork_trace!(
        "fork-trace: [process::register exit] pid={} task_id={} parent_pid={}",
        pid,
        task_id,
        parent_pid
    );
    pid
}

/// Return the PID of the currently-running task, or `0` if the running
/// task has no process table entry (e.g. the bootstrap kernel task).
///
/// ## Invariants enforced (#647)
///
/// - Must be called with interrupts enabled (IF=1). Spinning here with
///   IF=0 starves the timer ISR, which is the failure signature traced
///   to #478. Debug builds panic on violation; release builds skip the
///   check (no atomic read on the hot syscall path).
/// - The TABLE acquire uses an instrumented `try_lock` loop. If the
///   spin reaches [`CURRENT_PID_SOAK_THRESHOLD`] without progress, the
///   kernel panics in debug builds with a captured backtrace so the
///   regression is loud rather than silent.
pub fn current_pid() -> u32 {
    let task_id = crate::task::current_id();
    debug_assert!(
        is_if_set(),
        "current_pid() called with interrupts disabled — \
         spinning on TABLE with IF=0 starves the timer ISR (#478/#647)"
    );
    let table = lock_table_with_soak_check("current_pid");
    table.pid_of.get(&task_id).copied().unwrap_or(0)
}

/// Soak-loop ceiling for `try_lock` retries on TABLE before declaring
/// "stuck spinning". Tuned high enough that ordinary contention (a few
/// hundred ns of holder work) never trips, low enough that a wedged
/// holder is caught within seconds even on slow QEMU. Each pause is
/// ~1 cycle; ~1e8 iterations is ~30 ms on real hardware, multiple
/// seconds on un-accelerated QEMU.
pub const CURRENT_PID_SOAK_THRESHOLD: u64 = 100_000_000;

/// Acquire TABLE with an instrumented `try_lock` spin. Panics in debug
/// builds when the spin count exceeds [`CURRENT_PID_SOAK_THRESHOLD`] —
/// loud failure for the #478-class hang. Release builds use the plain
/// blocking `lock()` to keep the hot path branchless.
///
/// Used by every TABLE acquirer reachable from a userspace syscall —
/// in particular the wait4 wakeup path (`reap_child`, `has_children`,
/// `mark_zombie`, `reparent_children`) — so a #478/#710-class wedged
/// holder is caught loudly rather than as a silent serial-marker
/// dropout. Integration tests that exercise the helper directly are
/// permitted to call with IF=0 (the soak threshold still bounds any
/// genuine spin); the IF=1 invariant is enforced at the userspace-
/// reachable callers, not inside the helper.
#[inline]
fn lock_table_with_soak_check(caller: &'static str) -> spin::MutexGuard<'static, Table> {
    #[cfg(debug_assertions)]
    {
        let mut spins: u64 = 0;
        loop {
            if let Some(g) = TABLE.try_lock() {
                return g;
            }
            spins += 1;
            if spins == CURRENT_PID_SOAK_THRESHOLD {
                panic!(
                    "process::TABLE: {caller}() spin exceeded soak threshold \
                     ({CURRENT_PID_SOAK_THRESHOLD} iters) — holder appears wedged \
                     (likely lock-ordering violation; see #478/#647/#710)"
                );
            }
            core::hint::spin_loop();
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = caller;
        TABLE.lock()
    }
}

/// Cheap check for "interrupts currently enabled". Inline so the
/// debug-only assertion in [`current_pid`] doesn't add a function-call
/// cost when `debug_assertions` is off (the `debug_assert!` macro
/// elides the call entirely in release).
#[cfg(target_os = "none")]
#[inline]
fn is_if_set() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

/// Host-build stub: unit tests for this module run on the host where
/// real RFLAGS isn't meaningful. The IrqLock host harness models IF
/// state via an AtomicBool, but `current_pid` is exercised through
/// session-syscall tests that don't go through `task::current_id`, so
/// we report `true` here and let those tests focus on TABLE semantics.
#[cfg(not(target_os = "none"))]
#[inline]
fn is_if_set() -> bool {
    true
}

/// Mark `pid` as a zombie with `exit_status`, then wake any parents
/// sleeping in `waitpid`. TABLE is released before notify to satisfy
/// the lock-ordering rule described in the module docs.
///
/// ## Atomic publish (#710)
///
/// The Zombie state write and the `EXIT_EVENT` bump happen **under the
/// same TABLE critical section** so a waiter that observes either
/// `EXIT_EVENT > snap` or a zombie entry with the right parent
/// transitively observes the other. The previous shape (state under
/// TABLE, then `EXIT_EVENT.fetch_add` after TABLE drop) opened a
/// drain-order window the v1 simulator's `WakeupReorder` could
/// permute — see the seam-level analogue in
/// `simulator/tests/regression_501.rs`. Moving the bump inside TABLE
/// makes the reap path order-independent: any predicate evaluation
/// that takes TABLE and sees the zombie *also* observes the bumped
/// counter (and vice versa), regardless of which lock the caller
/// took first.
///
/// `notify_all` still happens after TABLE drop — the TABLE → inner
/// ordering rule documented in the module header forbids holding
/// TABLE across `WaitQueue::notify_all`'s `inner.lock()` acquire.
pub fn mark_zombie(pid: u32, status: i32) {
    debug_assert!(
        is_if_set(),
        "mark_zombie() called with interrupts disabled — \
         this is the wait4 wakeup path; spinning on TABLE/CHILD_WAIT \
         with IF=0 starves the timer ISR (#478/#647/#710)"
    );
    {
        let mut t = lock_table_with_soak_check("mark_zombie");
        if let Some(entry) = t.by_pid.get_mut(&pid) {
            entry.state = ProcessState::Zombie;
            entry.exit_status = Some(status);
        }
        // Bump the event counter inside the TABLE critical section so
        // the Zombie publish and the counter publish are atomically
        // observable to any other TABLE acquirer. A waiter that takes
        // TABLE (e.g. via `reap_child` / `has_children`) and sees the
        // pre-bump state will also see the pre-bump counter; a waiter
        // that sees the post-bump counter will, on the next TABLE
        // acquire, see the Zombie entry. Closes the seam-level
        // drain-order window from #710 / `regression_501`.
        EXIT_EVENT.fetch_add(1, Ordering::Release);
    }
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
    debug_assert!(
        is_if_set(),
        "reap_child() called with interrupts disabled — \
         this is the wait4 hot path (#710); spinning on TABLE with IF=0 \
         starves the timer ISR (#478/#647)"
    );
    let mut t = lock_table_with_soak_check("reap_child");
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
    debug_assert!(
        is_if_set(),
        "has_children() called with interrupts disabled — \
         wait4 entry path (#710); spinning on TABLE with IF=0 starves \
         the timer ISR (#478/#647)"
    );
    lock_table_with_soak_check("has_children")
        .by_pid
        .values()
        .any(|e| e.parent_pid == parent_pid)
}

/// Reparent all children of `dead_pid` to PID 1 so they are not left
/// orphaned. Called by the `exit()` syscall before marking the process
/// as a zombie.
pub fn reparent_children(dead_pid: u32) {
    debug_assert!(
        is_if_set(),
        "reparent_children() called with interrupts disabled — \
         exit() pre-mark_zombie path; spinning on TABLE with IF=0 \
         starves the timer ISR (#478/#647/#710)"
    );
    let mut t = lock_table_with_soak_check("reparent_children");
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
const ENOTTY: i64 = -25;

// ── Controlling-terminal accessors ─────────────────────────────────────────
//
// All cross-process inspection of `ProcessEntry.controlling_tty`, session,
// and pgrp happens here so TABLE locking stays inside the process module.
// The tty ioctl helpers in `crate::tty` call these and never take TABLE
// directly — keeps the lock-ordering documentation (TABLE → `tty.ctrl`)
// mechanically enforceable.

/// Return the controlling tty of `pid`, if any.
pub fn ctty_of(pid: u32) -> Option<Arc<Tty>> {
    TABLE
        .lock()
        .by_pid
        .get(&pid)
        .and_then(|e| e.controlling_tty.clone())
}

/// Set (or clear) the controlling tty of `pid`.
pub fn set_ctty(pid: u32, tty: Option<Arc<Tty>>) {
    if let Some(e) = TABLE.lock().by_pid.get_mut(&pid) {
        e.controlling_tty = tty;
    }
}

/// Session id of `pid`, if the entry exists.
pub fn session_of(pid: u32) -> Option<SessionId> {
    TABLE.lock().by_pid.get(&pid).map(|e| e.session_id)
}

/// Process-group id of `pid`, if the entry exists.
pub fn pgrp_of(pid: u32) -> Option<ProcessGroupId> {
    TABLE.lock().by_pid.get(&pid).map(|e| e.pgrp_id)
}

/// Raise `sig` on every task whose process-group id matches `pgid`.
/// Returns the number of tasks signaled. TABLE is released before the
/// raise calls to preserve the TABLE → signal/WaitQueue lock order.
pub fn raise_signal_on_pgrp(pgid: ProcessGroupId, sig: u8) -> usize {
    let task_ids: alloc::vec::Vec<usize> = {
        let t = TABLE.lock();
        t.by_pid
            .values()
            .filter(|e| e.pgrp_id == pgid)
            .map(|e| e.task_id)
            .collect()
    };
    let n = task_ids.len();
    for tid in task_ids {
        crate::signal::raise_signal_on_task(tid, sig);
    }
    n
}

/// Whether signal `sig` is blocked or ignored by the process with the
/// given `pid`. Returns `true` if either condition holds, `false` if the
/// pid has no process entry or the signal would be delivered normally.
/// TABLE is released before the signal mutex is taken.
pub fn is_signal_blocked_or_ignored(pid: u32, sig: u8) -> bool {
    use crate::signal::{sig_bit, Disposition};
    if sig == 0 || sig > crate::signal::NSIG {
        return false;
    }
    let signals = {
        let t = TABLE.lock();
        match t.by_pid.get(&pid) {
            Some(e) => Arc::clone(&e.signals),
            None => return false,
        }
    };
    let state = signals.lock();
    if state.blocked & sig_bit(sig) != 0 {
        return true;
    }
    matches!(state.dispositions[(sig - 1) as usize], Disposition::Ignore)
}

/// Whether `pid` is the session leader of its session
/// (POSIX: `session_id == pid`).
pub fn is_session_leader(pid: u32) -> bool {
    TABLE
        .lock()
        .by_pid
        .get(&pid)
        .map(|e| e.session_id == pid)
        .unwrap_or(false)
}

/// Whether `pgid` names an existing process group inside session `sid`.
/// A pgrp exists iff some live entry has that `pgrp_id`; it's in `sid`
/// iff that entry's `session_id == sid`.
pub fn pgrp_is_in_session(pgid: ProcessGroupId, sid: SessionId) -> bool {
    TABLE
        .lock()
        .by_pid
        .values()
        .any(|e| e.pgrp_id == pgid && e.session_id == sid)
}

/// If some session currently has `tty` as its controlling terminal,
/// return that session id. Uses `Arc::ptr_eq` — tty Arcs propagate on
/// fork via `Arc::clone`, so ptr-equality is sound.
pub fn session_using_tty(tty: &Arc<Tty>) -> Option<SessionId> {
    TABLE
        .lock()
        .by_pid
        .values()
        .find_map(|e| match &e.controlling_tty {
            Some(t) if Arc::ptr_eq(t, tty) => Some(e.session_id),
            _ => None,
        })
}

/// Atomic ctty acquisition: check session-leader, no existing ctty, and
/// `tty` unattached — if all hold, attach under a single TABLE → `tty.ctrl`
/// critical section. Returns `true` if the attach happened.
///
/// The check-then-set pattern in the caller is TOCTOU-vulnerable otherwise:
/// two leaders could each observe "no ctty / tty free" before either writes,
/// and the resulting state would violate the one-ctty-per-session invariant.
/// Collapsing everything into one critical section matches the documented
/// lock order (TABLE → `tty.ctrl`) and keeps the invariant mechanically.
pub fn try_acquire_ctty_atomic(pid: u32, tty: &Arc<Tty>) -> bool {
    if pid == 0 {
        return false;
    }
    let mut t = TABLE.lock();
    let Some(entry) = t.by_pid.get(&pid) else {
        return false;
    };
    if entry.session_id != pid {
        return false;
    }
    if entry.controlling_tty.is_some() {
        return false;
    }
    let sid = entry.session_id;
    let mut ctrl = tty.ctrl.lock();
    if ctrl.session.is_some() {
        return false;
    }
    t.by_pid.get_mut(&pid).unwrap().controlling_tty = Some(Arc::clone(tty));
    ctrl.session = Some(sid);
    ctrl.set_pgrp(Some(pid));
    true
}

/// Clear the controlling tty on every member of `sid`. Returns the
/// number of entries affected. Called by `TIOCNOTTY` on a session
/// leader and by `TIOCSCTTY(force)` when stealing from an old session.
pub fn clear_ctty_for_session(sid: SessionId) -> usize {
    let mut t = TABLE.lock();
    let mut n = 0;
    for e in t.by_pid.values_mut() {
        if e.session_id == sid && e.controlling_tty.is_some() {
            e.controlling_tty = None;
            n += 1;
        }
    }
    n
}

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

/// `getpgid(pid)` — return the pgrp id of `pid`, or of the caller if
/// `pid == 0`. Returns ESRCH for unknown pids.
///
/// `task::current_id()` is sampled *before* TABLE is acquired (and
/// only when `pid == 0`, where the caller's own id is needed) —
/// otherwise the call would invert the documented `TABLE → SCHED`
/// forbidden order (see module docs / #478 diagnostic).
pub fn sys_getpgid(pid: u32) -> i64 {
    let caller_task_id = if pid == 0 {
        Some(crate::task::current_id())
    } else {
        None
    };
    let t = TABLE.lock();
    let target = if let Some(tid) = caller_task_id {
        let self_pid = *t.pid_of.get(&tid).unwrap_or(&0);
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

/// `getsid(pid)` — return the session id of `pid`, or of the caller if
/// `pid == 0`. Returns ESRCH for unknown pids.
///
/// See [`sys_getpgid`] for the lock-ordering rationale.
pub fn sys_getsid(pid: u32) -> i64 {
    let caller_task_id = if pid == 0 {
        Some(crate::task::current_id())
    } else {
        None
    };
    let t = TABLE.lock();
    let target = if let Some(tid) = caller_task_id {
        let self_pid = *t.pid_of.get(&tid).unwrap_or(&0);
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

/// Collect every live pid whose `pgrp_id == pgid` into `out`.
///
/// Used by the N_TTY ISIG path to fan a signal out to the foreground
/// pgrp (#431). Takes `TABLE.lock()` only for the walk and releases it
/// before returning, so callers are free to re-enter the process table
/// (e.g. via `signal::raise_signal_on_pid`, which acquires the same
/// lock) while iterating the collected pids.
pub fn collect_pgrp_members(pgid: u32, out: &mut alloc::vec::Vec<u32>) {
    if pgid == 0 {
        return;
    }
    let t = TABLE.lock();
    for entry in t.by_pid.values() {
        if entry.pgrp_id == pgid && matches!(entry.state, ProcessState::Alive) {
            out.push(entry.pid);
        }
    }
}

/// Orphaned in the conservative sense the issue calls out: no live
/// member of `pgid` remains in the process table. Linux's real
/// `will_become_orphaned_pgrp` test also walks parents, but until
/// session reparenting lands we approximate with "no members" — which
/// matches the Linux behavior for a pgrp whose leader has exited and
/// whose members all followed.
pub fn pgrp_is_orphaned(pgid: u32) -> bool {
    if pgid == 0 {
        return true;
    }
    let t = TABLE.lock();
    !t.by_pid
        .values()
        .any(|e| e.pgrp_id == pgid && matches!(e.state, ProcessState::Alive))
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

    /// Set session + pgrp on an existing entry from a test.
    pub fn set_session_pgrp(pid: u32, session_id: SessionId, pgrp_id: ProcessGroupId) {
        patch(pid, |e| {
            e.session_id = session_id;
            e.pgrp_id = pgrp_id;
        });
    }

    pub const EPERM_I64: i64 = EPERM;
    pub const ESRCH_I64: i64 = ESRCH;
    pub const EINVAL_I64: i64 = EINVAL;
    pub const ENOTTY_I64: i64 = ENOTTY;
}
