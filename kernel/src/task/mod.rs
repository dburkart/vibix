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

pub mod env;
pub mod trace;

// Scheduler-core submodules. These pull in `arch`, `sync`, `x86_64`,
// and `crate::time` features that don't compile on the host, so they
// are gated to bare-metal builds. Host builds reach `task::env` only
// (RFC 0005 seam) so the `sched-mock` test path can compile and
// exercise `MockClock` / `MockTimerIrq` without dragging the real
// scheduler in.
#[cfg(target_os = "none")]
pub mod priority;
#[cfg(target_os = "none")]
mod scheduler;
#[cfg(target_os = "none")]
pub mod softirq;
#[cfg(target_os = "none")]
mod switch;
#[cfg(target_os = "none")]
mod task;

// Everything below is the scheduler core proper — `init` / `spawn` /
// `block_current` / `wake` / `sleep_ms` and the helpers behind them —
// extracted into `sched_core.rs` so this `mod.rs` stays small and the
// host-test exception above is obvious.
#[cfg(target_os = "none")]
mod sched_core;
#[cfg(target_os = "none")]
pub use sched_core::*;

// Host-only stubs for the three scheduler primitives that the
// `WaitQueue` / `process` modules need at function granularity:
// `current_id`, `wake`, `block_current`. The bare-metal scheduler
// owns these in `sched_core.rs`; on the host triple under
// `feature = "sched-mock"` we provide a thread-local-backed analogue
// so `simulator/` can drive `process::register` / `mark_zombie` /
// `reap_child` / the `wait4` snapshot loop on host (RFC 0008 / #790).
//
// Discipline (mirrors RFC 0005's seam contract): host stubs cover the
// **shape** of the bare-metal scheduler, not its semantics. Production
// `block_current` parks the task; the host stub is a no-op because the
// simulator drives the run sequentially and the only `wait_while`
// caller in scope (`wait4`) re-checks its condition under the same
// `WaitQueue.inner` mutex that `notify_all` takes — meaning a
// host-side `wait_while` whose condition is already false on entry
// returns immediately without ever needing to park (RFC 0008
// §"Single-thread parking semantics").
#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
mod host_stub;
#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
pub use host_stub::{block_current, current_id, set_current_id_for_test, wake, wake_pending};
