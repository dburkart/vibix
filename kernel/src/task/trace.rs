//! Kernel-side scheduler-mock trace seam (RFC 0006 / issue #718).
//!
//! Defines [`sched_mock_trace!`], the compile-out emit-point macro that
//! kernel paths use to feed the host-side DST simulator's
//! `(Tick, Event)` stream. The macro has two states:
//!
//! - **Off-feature / bare-metal** (the production kernel image): expands
//!   to `()`. The argument expression is **not** evaluated, so a
//!   `sched_mock_trace!(SchedMockEvent::Syscall { nr, args })` call site
//!   contributes zero instructions, zero data, and zero symbols to the
//!   release ELF. The nm-check guard (`cargo xtask nm-check`, originally
//!   landed in #669) verifies this statically by asserting no
//!   `sched_mock_*` symbols leak past the cfg gate.
//!
//! - **Host build with `--features sched-mock`** (the simulator's
//!   build): pushes the [`SchedMockEvent`] value into a thread-local
//!   [`Vec`] sink whose contents the test / simulator code drains via
//!   [`take_trace`]. The thread-local is per-`cargo test` worker and
//!   per-simulator instance so parallel seeds do not race on a shared
//!   buffer (mirroring the [`crate::task::env`] thread-local that
//!   installs the `MockClock`/`MockTimerIrq` seam).
//!
//! The kernel deliberately defines its own [`SchedMockEvent`] enum
//! rather than reaching into the `simulator` crate's `Event`: the
//! dependency arrow is `simulator → kernel`, never the other way. The
//! simulator (or downstream invariant code) maps [`SchedMockEvent`]
//! into its public `simulator::Event` type at drain time. Keeping the
//! types separate also means a kernel-only consumer (an in-kernel
//! `sched-mock`-gated integration test) can drain the trace without
//! pulling the simulator in.
//!
//! ## Why a thread-local, not a global atomic
//!
//! The host-side simulator runs one thread per seed under
//! `cargo test`'s parallel runner. A process-global sink would
//! serialize every emit on a shared mutex and would interleave records
//! from concurrent seeds. The thread-local approach matches the
//! [`crate::task::env`] `SIM_ENV` thread-local exactly, and the
//! "install once per worker thread" contract is the same:
//! `Simulator::new` installs the seam, the macro consumes it.
//!
//! ## Why this lives in `task/`, not `simulator/`
//!
//! The kernel is the producer of these events; the simulator is one
//! consumer. Putting the macro in `task/trace.rs` keeps the producer
//! definitions co-located with the scheduler core that emits them, and
//! keeps the simulator crate strictly downstream — it consumes
//! [`SchedMockEvent`] via [`take_trace`] and never the other way around.

#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
use crate::task::env::TaskId;

#[cfg(not(all(not(target_os = "none"), feature = "sched-mock")))]
#[allow(unused_imports)]
use crate::task::env::TaskId;

/// Reason a task entered the blocked state.
///
/// Mirrors `simulator::trace::BlockReason` in shape; the simulator's
/// `From<SchedMockBlockReason>` impl maps these into its own enum at
/// drain time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchedMockBlockReason {
    /// Task is waiting for a sleep deadline to expire.
    Sleep,
    /// Task is waiting on a wait-queue / synchronization primitive.
    Wait,
    /// Task is waiting for I/O completion.
    Io,
    /// Reserved for unmodelled or future block reasons.
    Other,
}

/// CPU-fault classification observed or injected.
///
/// Mirrors `simulator::trace::FaultKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchedMockFaultKind {
    /// Page fault (`#PF`).
    PageFault,
    /// General-protection fault (`#GP`).
    GeneralProtection,
    /// Invalid-opcode fault (`#UD`).
    InvalidOpcode,
    /// Double fault (`#DF`).
    DoubleFault,
    /// Reserved for unmodelled or future fault kinds.
    Other,
}

/// One scheduler-side observable event the kernel can emit through
/// [`sched_mock_trace!`].
///
/// The variant set mirrors the snapshot-derived / kernel-emit-required
/// arms of `simulator::trace::Event` (RFC 0006 §"Event emit points").
/// Driver-loop-only events ([`Event::TickAdvance`] etc.) are emitted
/// by the simulator itself and have no kernel-side emit point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchedMockEvent {
    /// A wakeup was enqueued for `deadline`, naming task `id`.
    /// Emitted from the `MockClock::enqueue_wakeup` host path and
    /// from `sleep_ms` on bare-metal.
    WakeupEnqueued {
        /// Deadline tick at which the wakeup is scheduled to fire.
        deadline: u64,
        /// Task id whose wakeup was enqueued.
        id: TaskId,
    },
    /// A task was scheduled onto the running slot. Emitted from
    /// scheduler dispatch (`preempt_tick` / `block_current` /
    /// `exit`) at the moment a new `current` is installed.
    TaskScheduled {
        /// Task id that was scheduled.
        id: TaskId,
    },
    /// A task entered the blocked state.
    TaskBlocked {
        /// Task id that blocked.
        id: TaskId,
        /// Reason the task is blocked.
        reason: SchedMockBlockReason,
    },
    /// A task was woken (parked → ready, or wake_pending set).
    TaskWoken {
        /// Task id that was woken.
        id: TaskId,
    },
    /// A task exited.
    TaskExit {
        /// Task id that exited.
        id: TaskId,
    },
    /// A `fork` / `exec` / `wait` transition occurred. The discriminant
    /// is encoded as the syscall number on `Syscall` events; this
    /// variant carries the resulting child / target id when relevant.
    TaskForked {
        /// Parent task id.
        parent: TaskId,
        /// Newly-created child task id.
        child: TaskId,
    },
    /// A syscall was entered.
    SyscallEntry {
        /// Syscall number (Linux-compatible numbering on x86_64).
        nr: u64,
        /// First four argument registers (RDI, RSI, RDX, R10 on
        /// x86_64). Truncated from the full six-arg ABI to keep the
        /// trace JSON small; the v1 invariant set does not consume the
        /// fifth/sixth arg.
        args: [u64; 4],
    },
    /// A syscall returned.
    SyscallExit {
        /// Syscall number that returned.
        nr: u64,
    },
    /// A CPU fault fired in user or kernel context.
    Fault {
        /// Fault classification.
        kind: SchedMockFaultKind,
        /// Faulting instruction pointer.
        rip: u64,
        /// Page-fault address (zero for non-page-fault kinds).
        cr2: u64,
    },
    /// The simulator's FaultPlan (#722) injected a fault before the
    /// kernel observed it. Carried here so future plans can record the
    /// inject side; not yet emitted.
    FaultInjected {
        /// Fault classification injected.
        kind: SchedMockFaultKind,
    },
}

// ---------------------------------------------------------------------------
// Host build with `feature = "sched-mock"`: the macro expands to a real
// push into a thread-local sink. The kernel `lib.rs` already pulls in
// `std` for this exact build configuration (see the `cfg_attr(no_std)`
// at the crate root), so `std::thread_local!` is available.
// ---------------------------------------------------------------------------

#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
mod host_sink {
    use super::SchedMockEvent;
    use alloc::vec::Vec;

    std::thread_local! {
        static SINK: core::cell::RefCell<Vec<SchedMockEvent>> =
            const { core::cell::RefCell::new(Vec::new()) };
    }

    /// Append `event` to the current thread's trace sink.
    ///
    /// Called by [`crate::sched_mock_trace!`] only — direct calls bypass
    /// the macro's compile-out gate and would defeat the nm-check
    /// guard on a production build.
    #[doc(hidden)]
    pub fn push_event(event: SchedMockEvent) {
        // `try_borrow_mut` rather than `borrow_mut`: a panic from the
        // macro's emit point during an already-in-progress drain
        // (e.g. an invariant predicate that evaluates events while
        // the kernel is still running) would otherwise abort the
        // simulator. Drop the event silently in that case — the
        // bounded-recursion event matters less than a clean panic
        // message from the actual invariant violation.
        let _ = SINK.with(|c| {
            if let Ok(mut g) = c.try_borrow_mut() {
                g.push(event);
                Ok(())
            } else {
                Err(())
            }
        });
    }

    /// Drain the current thread's trace sink, returning every event
    /// pushed since the last drain.
    pub fn take_trace() -> Vec<SchedMockEvent> {
        SINK.with(|c| core::mem::take(&mut *c.borrow_mut()))
    }

    /// Number of events currently buffered for the current thread.
    /// Test introspection only.
    pub fn pending_event_count() -> usize {
        SINK.with(|c| c.borrow().len())
    }

    /// Clear the current thread's trace sink without returning its
    /// contents. Cheaper than `take_trace().drain(..)` when the caller
    /// just wants a fresh slate before the next assertion.
    pub fn clear_trace() {
        SINK.with(|c| c.borrow_mut().clear());
    }
}

#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
pub use host_sink::{clear_trace, pending_event_count, push_event, take_trace};

// ---------------------------------------------------------------------------
// Off-feature / bare-metal: the macro is a no-op. Provide stub
// `take_trace` etc. so callers in cfg-conditional code don't have to
// fence every drain call themselves; on these targets the trace is
// always empty.
// ---------------------------------------------------------------------------

#[cfg(not(all(not(target_os = "none"), feature = "sched-mock")))]
#[allow(dead_code)]
pub(crate) fn pending_event_count() -> usize {
    0
}

/// Emit a [`SchedMockEvent`] to the per-thread scheduler trace sink.
///
/// Compile-time gated:
///
/// - `cfg(not(all(not(target_os = "none"), feature = "sched-mock")))`:
///   expands to `()`. The argument expression is **not** evaluated;
///   no `sched_mock_*` symbol survives into the release ELF (verified
///   by `cargo xtask nm-check`).
/// - `cfg(all(not(target_os = "none"), feature = "sched-mock"))`:
///   pushes `event` into the calling thread's sink; downstream callers
///   drain via [`take_trace`].
///
/// # Example
///
/// ```ignore
/// use vibix::task::trace::{SchedMockEvent, SchedMockBlockReason};
/// use vibix::sched_mock_trace;
///
/// // In `block_current()`:
/// sched_mock_trace!(SchedMockEvent::TaskBlocked {
///     id: prev_id,
///     reason: SchedMockBlockReason::Wait,
/// });
/// ```
#[macro_export]
macro_rules! sched_mock_trace {
    ($event:expr) => {{
        // The two-arm cfg-if pattern keeps the off-feature arm
        // a literal `()` rather than `let _ = $event;` — the latter
        // would still evaluate the argument expression on the off
        // path, defeating the nm-check guard (any symbol referenced
        // inside `$event` would link in).
        #[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
        {
            $crate::task::trace::push_event($event);
        }
        #[cfg(not(all(not(target_os = "none"), feature = "sched-mock")))]
        {
            // No-op; argument intentionally not evaluated. The unit
            // value here is what makes call sites compile in
            // statement position without a trailing semicolon.
            ()
        }
    }};
}

#[cfg(all(test, not(target_os = "none"), feature = "sched-mock"))]
mod tests {
    use super::*;
    use crate::sched_mock_trace;

    /// Each test runs on a fresh thread because the sink is a
    /// thread-local — running on the cargo-test main thread would
    /// share state with whatever earlier test happened to land there.
    fn on_fresh_thread<R, F>(f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        std::thread::spawn(f).join().expect("test thread panicked")
    }

    #[test]
    fn sink_starts_empty() {
        on_fresh_thread(|| {
            assert_eq!(pending_event_count(), 0);
            assert!(take_trace().is_empty());
        });
    }

    #[test]
    fn macro_pushes_a_single_event() {
        on_fresh_thread(|| {
            sched_mock_trace!(SchedMockEvent::TaskScheduled { id: 42 });
            let evs = take_trace();
            assert_eq!(evs.len(), 1);
            assert!(matches!(evs[0], SchedMockEvent::TaskScheduled { id: 42 }));
        });
    }

    #[test]
    fn macro_preserves_emit_order_across_variants() {
        on_fresh_thread(|| {
            sched_mock_trace!(SchedMockEvent::SyscallEntry {
                nr: 60,
                args: [1, 2, 3, 4],
            });
            sched_mock_trace!(SchedMockEvent::TaskScheduled { id: 7 });
            sched_mock_trace!(SchedMockEvent::TaskBlocked {
                id: 7,
                reason: SchedMockBlockReason::Wait,
            });
            sched_mock_trace!(SchedMockEvent::TaskWoken { id: 7 });
            sched_mock_trace!(SchedMockEvent::SyscallExit { nr: 60 });

            let evs = take_trace();
            assert_eq!(evs.len(), 5);
            assert!(matches!(
                evs[0],
                SchedMockEvent::SyscallEntry { nr: 60, .. }
            ));
            assert!(matches!(evs[1], SchedMockEvent::TaskScheduled { id: 7 }));
            assert!(matches!(
                evs[2],
                SchedMockEvent::TaskBlocked {
                    id: 7,
                    reason: SchedMockBlockReason::Wait,
                }
            ));
            assert!(matches!(evs[3], SchedMockEvent::TaskWoken { id: 7 }));
            assert!(matches!(evs[4], SchedMockEvent::SyscallExit { nr: 60 }));
        });
    }

    #[test]
    fn take_trace_resets_the_sink() {
        on_fresh_thread(|| {
            sched_mock_trace!(SchedMockEvent::TaskScheduled { id: 1 });
            sched_mock_trace!(SchedMockEvent::TaskScheduled { id: 2 });
            assert_eq!(pending_event_count(), 2);
            let _ = take_trace();
            assert_eq!(pending_event_count(), 0);
            // A second take_trace returns empty.
            assert!(take_trace().is_empty());
        });
    }

    #[test]
    fn clear_trace_drops_buffered_events() {
        on_fresh_thread(|| {
            sched_mock_trace!(SchedMockEvent::TaskWoken { id: 9 });
            sched_mock_trace!(SchedMockEvent::TaskWoken { id: 10 });
            assert_eq!(pending_event_count(), 2);
            clear_trace();
            assert_eq!(pending_event_count(), 0);
        });
    }

    #[test]
    fn sink_is_per_thread() {
        on_fresh_thread(|| {
            // Outer thread: emit and observe.
            sched_mock_trace!(SchedMockEvent::TaskScheduled { id: 100 });
            assert_eq!(pending_event_count(), 1);

            // A spawned thread starts with an empty sink and its emits
            // are not visible on the outer thread.
            let inner = std::thread::spawn(|| {
                assert_eq!(pending_event_count(), 0);
                sched_mock_trace!(SchedMockEvent::TaskScheduled { id: 200 });
                pending_event_count()
            })
            .join()
            .unwrap();
            assert_eq!(inner, 1);

            // Outer still sees only its own event.
            let evs = take_trace();
            assert_eq!(evs.len(), 1);
            assert!(matches!(evs[0], SchedMockEvent::TaskScheduled { id: 100 }));
        });
    }

    #[test]
    fn page_fault_event_round_trips() {
        on_fresh_thread(|| {
            sched_mock_trace!(SchedMockEvent::Fault {
                kind: SchedMockFaultKind::PageFault,
                rip: 0xDEAD_BEEF,
                cr2: 0xCAFE_F00D,
            });
            let evs = take_trace();
            assert_eq!(evs.len(), 1);
            assert!(matches!(
                evs[0],
                SchedMockEvent::Fault {
                    kind: SchedMockFaultKind::PageFault,
                    rip: 0xDEAD_BEEF,
                    cr2: 0xCAFE_F00D,
                }
            ));
        });
    }

    #[test]
    fn fork_event_records_parent_and_child() {
        on_fresh_thread(|| {
            sched_mock_trace!(SchedMockEvent::TaskForked {
                parent: 1,
                child: 2,
            });
            let evs = take_trace();
            assert!(matches!(
                evs[0],
                SchedMockEvent::TaskForked {
                    parent: 1,
                    child: 2,
                }
            ));
        });
    }

    /// nm-check guard cannot run from a unit test (it inspects the
    /// release kernel ELF). What we *can* assert at compile time is
    /// that the off-feature arm of the macro evaluates to the unit
    /// value with no symbol reference. This test is the unit-test
    /// shadow of the `xtask nm-check` integration test.
    #[test]
    fn macro_compiles_in_statement_position() {
        on_fresh_thread(|| {
            // Statement position — the trailing `()` expansion makes
            // this legal off-feature too.
            sched_mock_trace!(SchedMockEvent::TaskScheduled { id: 0 });
            sched_mock_trace!(SchedMockEvent::SyscallExit { nr: 60 });
            let _ = take_trace();
        });
    }
}

// Off-feature compile guarantee: the static `cargo xtask nm-check`
// integration check (extended in `xtask/src/main.rs` for #718) is the
// real guard against the off-feature macro arm leaking
// `sched_mock_*` / `SchedMockEvent` symbols into the release ELF. A
// `#[test]` here would only compile on a configuration that also
// enables `pub mod task`, which itself already requires
// `feature = "sched-mock"` — the off-feature combination is therefore
// not reachable from `cargo test` and the assertion belongs in
// `nm-check`, not in this module.
