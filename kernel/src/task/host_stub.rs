//! Host-only stubs for the bare-metal scheduler primitives that
//! [`crate::sync::WaitQueue`] and [`crate::process`] consume at function
//! granularity.
//!
//! On bare metal, [`crate::task::sched_core`] owns `current_id`,
//! `wake`, and `block_current`; under
//! `cfg(all(not(target_os = "none"), feature = "sched-mock"))` we
//! synthesise the same surface using a thread-local "current task id"
//! and a thread-local "wake_pending" flag.
//!
//! ## Why this is a faithful host arm of the seam
//!
//! The simulator (`simulator/`) drives `process::register`,
//! `process::mark_zombie`, and the `wait4` snapshot-and-park loop
//! sequentially on a single thread; there is never more than one
//! "running task" at a time. The `wait_while` caller in `wait4`'s arm
//! checks a snapshot-equality predicate under `WaitQueue.inner`'s
//! Mutex; if the simulator dispatches `sys_exit` (which calls
//! `mark_zombie`, bumping `EXIT_EVENT` under TABLE) **before** the
//! parent's `sys_wait4`, the parent's `cond()` is already false on
//! entry, `wait_while` returns immediately, and the host stub's
//! no-op `block_current` is never observable. RFC 0008 §"Single-thread
//! parking semantics" documents the exhaustive cases.
//!
//! ## What this is NOT
//!
//! These are **not** a host-side scheduler. They cannot park a task
//! and wake it from a different host thread; if a future host caller
//! tries to `block_current` on a wakeup that requires another thread
//! to fire, the call will spin in `wait_while`'s loop forever. The
//! simulator's run loop is single-threaded by design (RFC 0006
//! §"The driver loop"); this stub matches that constraint.

use core::cell::Cell;

std::thread_local! {
    /// Per-thread "current task id". The simulator sets this via
    /// [`set_current_id_for_test`] when it wants to dispatch a syscall
    /// in the context of a particular task (e.g. parent vs child); the
    /// kernel-side `process::current_pid` reads it through
    /// [`current_id`] and looks the resulting task id up in TABLE.
    static CURRENT_ID: Cell<usize> = const { Cell::new(0) };
    /// Per-thread `wake_pending` flag. Mirrors the `wake_pending`
    /// counter the bare-metal scheduler keeps per task: a `wake` that
    /// arrives before the matching `block_current` flips the flag, and
    /// the next `block_current` consumes it and returns immediately.
    /// Single-threaded so a `Cell<bool>` suffices.
    static WAKE_PENDING: Cell<bool> = const { Cell::new(false) };
}

/// Return the simulator-installed "current task id" for this thread.
///
/// Initial value is `0` — matches the bare-metal "no task running yet"
/// state; `process::current_pid` returns `0` for unknown task ids,
/// which is the same observable behaviour as the kernel's
/// pre-`task::init` boot phase.
pub fn current_id() -> usize {
    CURRENT_ID.with(|c| c.get())
}

/// Install a synthetic "current task id" for the duration of one
/// simulator-driven syscall dispatch. Returns the previous id so a
/// caller can restore it after dispatch (the simulator stores per-task
/// register state externally).
///
/// The name carries `_for_test` because no production code path on
/// host is allowed to call this; only `simulator::install_init_process`
/// and `simulator::dispatch_syscall` reach for it (they live behind
/// the same `sched-mock` feature gate).
pub fn set_current_id_for_test(id: usize) -> usize {
    CURRENT_ID.with(|c| c.replace(id))
}

/// Park the calling task until a `wake` matching the current id has
/// been observed.
///
/// On bare metal this calls into the scheduler and a context switch
/// happens. On host with `sched-mock` we model "park" as "consume the
/// wake_pending flag and return"; if no wake has arrived, we still
/// return — the `wait_while` loop above us re-checks its condition
/// under the queue mutex and will re-enqueue on the next iteration if
/// progress hasn't happened, which is the simulator's single-thread
/// safety net (RFC 0008 §"Single-thread parking semantics").
pub fn block_current() {
    WAKE_PENDING.with(|c| c.set(false));
}

/// Wake task `id`. On host this just sets the wake_pending flag if
/// `id` matches the current task; cross-thread waking is not modelled.
pub fn wake(id: usize) {
    let cur = current_id();
    if id == cur {
        WAKE_PENDING.with(|c| c.set(true));
    }
}

/// Test-introspection helper: read the wake_pending flag without
/// consuming it.
pub fn wake_pending() -> bool {
    WAKE_PENDING.with(|c| c.get())
}
