//! Scheduler / IRQ seam — trait definitions only.
//!
//! Phase 1 of [RFC 0005](../../../docs/RFC/0005-scheduler-irq-seam.md):
//! the scheduler core's two injected dependencies, defined here as
//! traits so production wiring (PIT/HPET/APIC adapters) and test/sim
//! wiring (mocks, future host-side simulator) can plug in without
//! either side reaching into the other's globals.
//!
//! This module is intentionally **traits-only** in this PR — no
//! adapters, no `env()` accessor, no callers migrated. Issue #666
//! lands the `HwClock` / `HwIrq` adapters and the `env()` accessor;
//! issue #667 migrates `preempt_tick` / `sleep_ms` / signal callers
//! through the seam; issue #668 lands `MockClock` / `MockIrqSource`.
//!
//! ## Discipline (RFC 0005, "Discipline" section)
//!
//! > A `Clock` or `IrqSource` trait method is added only when a
//! > second implementation actually needs it.
//!
//! Speculative methods are rejected. The first new method that
//! appears is the one the host-side simulator (Phase 2) needs first,
//! and that PR is where its semantics get debated. Per-CPU state,
//! IDT install, IOAPIC redirection, and IPI send are explicitly
//! Phase 2 and do **not** belong on these traits today.
//!
//! [RFC 0005]: ../../../docs/RFC/0005-scheduler-irq-seam.md

use alloc::vec::Vec;

/// Typed task identifier used at the scheduler / clock seam.
///
/// Aliased to `usize` today (matches `task::current_id` and the
/// existing `time::{enqueue_wakeup, drain_expired}` signatures); the
/// alias exists so a future generation-counted id refactor can change
/// the underlying type without silently breaking `Clock`
/// implementations.
pub type TaskId = usize;

/// Monotonic tick count since boot.
///
/// Opaque newtype with a `pub(crate)` field; callers must use the
/// methods on `Tick` rather than reaching into the `u64` directly.
/// The field is `pub(crate)` so the production `HwClock` adapter
/// (issue #666) can construct a `Tick` from `crate::time::ticks()`
/// without ceremony.
///
/// ## Unit invariant
///
/// `Tick` units must be uniform across all `Clock` impls within a
/// single boot. Today every impl uses PIT ticks (10 ms); when the
/// LAPIC-timer migration lands, every impl in that build switches
/// together — there is no mixed-unit world. Violating this invariant
/// breaks Liskov substitution and is a correctness bug, not a
/// performance one.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Tick(pub(crate) u64);

impl Tick {
    /// Add `ticks` to `self`, returning `None` on overflow.
    pub fn checked_add(self, ticks: u64) -> Option<Self> {
        self.0.checked_add(ticks).map(Tick)
    }

    /// Add `ticks` to `self`, saturating at `u64::MAX` on overflow.
    pub fn saturating_add(self, ticks: u64) -> Self {
        Tick(self.0.saturating_add(ticks))
    }

    /// Underlying tick count. Prefer the typed methods; this exists
    /// for adapters that need to bridge into `u64`-typed APIs (today:
    /// `crate::time::*`).
    pub fn raw(self) -> u64 {
        self.0
    }
}

/// Source of monotonic time and one-shot future tick wakeups for the
/// scheduler. The scheduler never reads a clock register or arms a
/// timer directly — it goes through this trait.
///
/// ## IRQ-context contract
///
/// All three methods MUST be safe to call from both task context and
/// interrupt context. Implementors that hold internal state across
/// methods MUST mask IRQs while held (today: see
/// [`crate::sync::IrqLock`], which `time::WAKEUPS` already uses). A
/// non-IRQ-safe `Clock` impl is a soundness bug — `preempt_tick`
/// will deadlock the first time the timer IRQ lands while a syscall
/// holds the impl's internal lock.
///
/// ## Init-order contract
///
/// `Clock` impls MUST be safe to call any time after the global
/// allocator is up — earlier than `task::init()`. Several boot-phase
/// paths (TSC calibration, early `serial_println` timestamps) reach
/// the clock before the scheduler exists. The production `HwClock`
/// is zero-sized and trivially satisfies this; non-ZST impls (mocks,
/// simulator) must either initialize lazily on first call or document
/// their init-order requirement and have the boot sequence install
/// them before that point.
pub trait Clock: Sync {
    /// Current monotonic tick count. IRQ-safe.
    fn now(&self) -> Tick;

    /// Drain all wakeup ids whose deadline is `<= now`.
    ///
    /// The implementor owns the deadline structure (today:
    /// `crate::time::WAKEUPS`); the scheduler only consumes the
    /// drained ids. Called from the timer ISR — must be IRQ-safe.
    ///
    /// Returns a [`Vec<TaskId>`] (allocation in IRQ-tail context).
    /// This matches the existing `time::drain_expired` contract and
    /// is preserved deliberately; replacing it with an iterator
    /// would require pinning the lock across the iterator lifetime,
    /// which the scheduler cannot promise. Any future change here
    /// is its own RFC.
    fn drain_expired(&self, now: Tick) -> Vec<TaskId>;

    /// Enqueue task `id` for a wakeup at `deadline`.
    ///
    /// Idempotent on `(deadline, id)` pairs. Called from task
    /// context (`sleep_ms`) and potentially from IRQ context (future
    /// timeout-bearing syscalls during signal-delivery wakeup) —
    /// must be IRQ-safe.
    fn enqueue_wakeup(&self, deadline: Tick, id: TaskId);
}

/// Source of preemption-relevant interrupts for the scheduler.
///
/// Scoped to the *scheduler's* view of IRQs only: device drivers
/// continue to ack their own IRQs through `crate::arch::*` directly.
/// One-shot IDT install, IOAPIC redirection programming, and IPI
/// send are **not** part of this trait (RFC 0005 §"Alternatives
/// Considered" — wider trait surface rejected for v1). Despite the
/// generic-sounding name, today this means a single method.
pub trait IrqSource: Sync {
    /// Acknowledge the timer IRQ that drove the current
    /// `preempt_tick` call. Today: LAPIC EOI write; on legacy PIC:
    /// PIC EOI. Called from the timer ISR — must be IRQ-safe.
    fn ack_timer(&self);
}

// ---------------------------------------------------------------------------
// Production adapters (Phase 1 wave 2, issue #666).
//
// Zero-sized wrappers over the existing `crate::time::*` and
// `crate::arch::*` globals. Each method is a pure forwarding call so
// the equivalence audit is mechanical: `HwClock::now()` is exactly
// `crate::time::ticks()` boxed into a `Tick`, etc. No added
// synchronization (no `Once`, `Mutex`, or atomic load) sits between a
// caller and the underlying global — the `static` adapter values are
// `'static` ZSTs and `env()` is a const-shaped function returning two
// references.
//
// `HwIrq` and `env()` depend on `crate::arch::*` and so are gated to
// `target_os = "none"` builds; the trait definitions above stay
// host-buildable for the future `MockClock` / `MockIrqSource`
// (issue #668).
// ---------------------------------------------------------------------------

/// Production `Clock` over the PIT tick counter and the
/// `crate::time::WAKEUPS` deadline map.
pub struct HwClock;

impl Clock for HwClock {
    fn now(&self) -> Tick {
        Tick(crate::time::ticks())
    }

    fn drain_expired(&self, now: Tick) -> Vec<TaskId> {
        crate::time::drain_expired(now.0)
    }

    fn enqueue_wakeup(&self, deadline: Tick, id: TaskId) {
        crate::time::enqueue_wakeup(deadline.0, id);
    }
}

/// Production `IrqSource` over the LAPIC end-of-interrupt path.
#[cfg(target_os = "none")]
pub struct HwIrq;

#[cfg(target_os = "none")]
impl IrqSource for HwIrq {
    fn ack_timer(&self) {
        crate::arch::ack_timer_irq();
    }
}

/// Singleton `HwClock` handed out by [`env`].
pub static HW_CLOCK: HwClock = HwClock;

/// Singleton `HwIrq` handed out by [`env`].
#[cfg(target_os = "none")]
pub static HW_IRQ: HwIrq = HwIrq;

/// Production wire-up of the scheduler / IRQ seam.
///
/// Returns the singleton `Clock` + `IrqSource` pair that the scheduler
/// and the timer ISR will route through once issue #667 migrates the
/// callers. Body is intentionally a single tuple of two `&'static`
/// references — no `Once`, no `Mutex`, no atomic load — so that the
/// production path adds zero synchronization vs. the pre-seam direct
/// calls (RFC 0005 Equivalence condition 2).
#[cfg(target_os = "none")]
pub fn env() -> (&'static dyn Clock, &'static dyn IrqSource) {
    (&HW_CLOCK, &HW_IRQ)
}

/// Debug-only invariant: the references returned by [`env`] are the
/// production singletons.
///
/// Lives here in `env.rs` rather than in the caller because
/// `core::ptr::eq` on `&dyn Trait` compares both the data pointer
/// **and** the vtable pointer, and the vtable for a given trait/type
/// pair is materialized per-codegen-unit. A check that compares
/// `env()`'s output against `&HW_CLOCK` from a different module would
/// see two distinct vtable pointers (same `data` pointer, different
/// `vtable`) and spuriously fire — which is exactly what bit the
/// `task::init` call site after `sched_core` was extracted into its
/// own module (RFC 0005 wave 3, #668). Keeping both materialization
/// sites inside the same compilation unit (this function) sidesteps
/// the issue while preserving the runtime check.
#[cfg(target_os = "none")]
pub fn assert_production_env() -> bool {
    let (clock, irq) = env();
    let hw_clock: &dyn Clock = &HW_CLOCK;
    let hw_irq: &dyn IrqSource = &HW_IRQ;
    core::ptr::eq(clock, hw_clock) && core::ptr::eq(irq, hw_irq)
}

// ---------------------------------------------------------------------------
// Mock impls (Phase 1 wave 3, issue #668).
//
// `MockClock` and `MockIrqSource` are non-production `Clock` /
// `IrqSource` implementations used by host-side unit tests, future
// in-kernel `sched-mock`-gated integration tests, and (eventually) the
// Phase 2 host-side simulator. They are gated by the `sched-mock`
// Cargo feature *only* (no `target_os` exception) so a release kernel
// build cannot pull them in: the nm-check guard (#669) statically
// verifies the symbols don't appear in the release ELF.
//
// Discipline: the mocks own *all* their state internally and never
// touch `crate::time::WAKEUPS` or `crate::arch::*`. That isolation is
// what makes `with_mock_env`-driven tests deterministic — a test
// advancing `MockClock` cannot accidentally race with the production
// PIT tick handler updating `time::TICKS`.
// ---------------------------------------------------------------------------

/// Mock `Clock` for deterministic scheduler tests and the future host-side
/// simulator.
///
/// Time advances only on explicit [`MockClock::tick`] / [`MockClock::advance`]
/// calls — never spontaneously. `enqueue_wakeup` records `(deadline, id)`
/// pairs in an internal table; `drain_expired` drains everything with
/// `deadline <= now`. The implementation is independent of
/// `crate::time::WAKEUPS` so a test driving a `MockClock` cannot collide
/// with the production PIT tick path.
///
/// Uses `spin::Mutex` rather than [`crate::sync::IrqLock`] because the
/// mock is not reachable on a real boot — there is no ISR that could
/// re-enter it. On the host there is no IRQ context at all; under a
/// future in-kernel sim test, the mock is the only `Clock` installed and
/// the production timer ISR is not arming preempt ticks against it.
#[cfg(feature = "sched-mock")]
pub struct MockClock {
    inner: spin::Mutex<MockClockState>,
}

#[cfg(feature = "sched-mock")]
struct MockClockState {
    now: u64,
    /// Pending wakeups keyed by deadline. Mirrors the
    /// `time::WAKEUPS` shape exactly so callers see identical
    /// drain-order semantics.
    wakeups: alloc::collections::BTreeMap<u64, Vec<TaskId>>,
}

#[cfg(feature = "sched-mock")]
impl MockClock {
    /// Construct a `MockClock` whose initial tick count is `seed`. The
    /// wakeup table starts empty.
    ///
    /// `seed` is exposed so tests (and future seeded-replay simulator
    /// runs) can start from a non-zero tick — e.g. to exercise overflow
    /// edges of `Tick::checked_add` without spinning the clock forward
    /// for billions of ticks first.
    pub const fn new(seed: u64) -> Self {
        Self {
            inner: spin::Mutex::new(MockClockState {
                now: seed,
                wakeups: alloc::collections::BTreeMap::new(),
            }),
        }
    }

    /// Advance the clock by exactly one tick. Convenience wrapper over
    /// [`MockClock::advance`] for tests that step in single-tick
    /// increments.
    pub fn tick(&self) {
        self.advance(1);
    }

    /// Advance the clock by `ticks`, saturating at `u64::MAX`. Does not
    /// drain wakeups — callers do that explicitly via the [`Clock`] trait
    /// so tests can observe the pre-drain and post-drain state separately.
    pub fn advance(&self, ticks: u64) {
        let mut g = self.inner.lock();
        g.now = g.now.saturating_add(ticks);
    }

    /// Number of pending wakeup entries. Test introspection only.
    pub fn pending_wakeups(&self) -> usize {
        self.inner.lock().wakeups.values().map(|v| v.len()).sum()
    }
}

#[cfg(feature = "sched-mock")]
impl Clock for MockClock {
    fn now(&self) -> Tick {
        Tick(self.inner.lock().now)
    }

    fn drain_expired(&self, now: Tick) -> Vec<TaskId> {
        let mut g = self.inner.lock();
        let mut out = Vec::new();
        // Split off keys > now; the remainder is everything <= now.
        let keep = g.wakeups.split_off(&(now.0 + 1));
        let expired = core::mem::replace(&mut g.wakeups, keep);
        for (_deadline, ids) in expired {
            out.extend(ids);
        }
        out
    }

    fn enqueue_wakeup(&self, deadline: Tick, id: TaskId) {
        let mut g = self.inner.lock();
        g.wakeups.entry(deadline.0).or_default().push(id);
    }
}

/// Mock `IrqSource` for deterministic scheduler tests.
///
/// `ack_timer` is a no-op on the wire (there is no LAPIC / PIC behind
/// the mock to acknowledge), but the call is recorded for assertions and
/// a separate [`MockIrqSource::inject_timer`] entry point lets tests
/// simulate a timer IRQ landing — for the v1 trait surface that just
/// records an inject; future trait methods (post-Phase 2) may grow
/// observable side effects.
#[cfg(feature = "sched-mock")]
pub struct MockIrqSource {
    inner: spin::Mutex<MockIrqState>,
}

#[cfg(feature = "sched-mock")]
#[derive(Default)]
struct MockIrqState {
    ack_calls: u64,
    pending_timer_injects: u64,
}

#[cfg(feature = "sched-mock")]
impl MockIrqSource {
    /// Construct a fresh mock IRQ source with both counters at zero.
    pub const fn new() -> Self {
        Self {
            inner: spin::Mutex::new(MockIrqState {
                ack_calls: 0,
                pending_timer_injects: 0,
            }),
        }
    }

    /// Inject a virtual timer IRQ. Increments the pending-inject counter
    /// so tests can observe how many IRQs have been queued versus
    /// acknowledged. The simulator (Phase 2) will use this to drive
    /// preempt ticks at chosen simulated-time points.
    pub fn inject_timer(&self) {
        self.inner.lock().pending_timer_injects += 1;
    }

    /// Number of times [`IrqSource::ack_timer`] has been called.
    pub fn ack_count(&self) -> u64 {
        self.inner.lock().ack_calls
    }

    /// Number of timer IRQs injected by [`MockIrqSource::inject_timer`]
    /// minus the number acknowledged. Should drop to zero after the
    /// scheduler processes every injected tick.
    pub fn pending_timers(&self) -> u64 {
        let g = self.inner.lock();
        g.pending_timer_injects.saturating_sub(g.ack_calls)
    }
}

#[cfg(feature = "sched-mock")]
impl Default for MockIrqSource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "sched-mock")]
impl IrqSource for MockIrqSource {
    fn ack_timer(&self) {
        self.inner.lock().ack_calls += 1;
    }
}

#[cfg(all(test, feature = "sched-mock"))]
mod mock_tests {
    use super::*;

    #[test]
    fn mock_clock_advances_only_on_explicit_tick() {
        let c = MockClock::new(0);
        assert_eq!(c.now().raw(), 0);
        c.tick();
        assert_eq!(c.now().raw(), 1);
        c.advance(9);
        assert_eq!(c.now().raw(), 10);
    }

    #[test]
    fn mock_clock_seed_is_honored() {
        let c = MockClock::new(1_000);
        assert_eq!(c.now().raw(), 1_000);
    }

    #[test]
    fn mock_clock_advance_saturates() {
        let c = MockClock::new(u64::MAX - 1);
        c.advance(10);
        assert_eq!(c.now().raw(), u64::MAX);
    }

    #[test]
    fn drain_returns_only_expired_ids_in_deadline_order() {
        let c = MockClock::new(0);
        c.enqueue_wakeup(Tick(5), 100);
        c.enqueue_wakeup(Tick(3), 200);
        c.enqueue_wakeup(Tick(10), 300);

        // now=4 → drains deadline 3 only.
        let drained = c.drain_expired(Tick(4));
        assert_eq!(drained, alloc::vec![200]);
        assert_eq!(c.pending_wakeups(), 2);

        // now=5 → drains deadline 5 only.
        let drained = c.drain_expired(Tick(5));
        assert_eq!(drained, alloc::vec![100]);

        // now=20 → drains the rest.
        let drained = c.drain_expired(Tick(20));
        assert_eq!(drained, alloc::vec![300]);
        assert_eq!(c.pending_wakeups(), 0);
    }

    #[test]
    fn multiple_ids_share_a_deadline() {
        let c = MockClock::new(0);
        c.enqueue_wakeup(Tick(7), 1);
        c.enqueue_wakeup(Tick(7), 2);
        c.enqueue_wakeup(Tick(7), 3);
        let mut drained = c.drain_expired(Tick(7));
        drained.sort_unstable();
        assert_eq!(drained, alloc::vec![1, 2, 3]);
    }

    #[test]
    fn mock_irq_records_ack_and_inject() {
        let irq = MockIrqSource::new();
        assert_eq!(irq.ack_count(), 0);
        assert_eq!(irq.pending_timers(), 0);

        irq.inject_timer();
        irq.inject_timer();
        assert_eq!(irq.pending_timers(), 2);

        irq.ack_timer();
        assert_eq!(irq.ack_count(), 1);
        assert_eq!(irq.pending_timers(), 1);

        irq.ack_timer();
        assert_eq!(irq.pending_timers(), 0);
    }

    /// End-to-end: advance the clock, inject a timer IRQ, observe a
    /// wakeup. This is the proof-of-life flow the Phase 2 simulator and
    /// future `with_mock_env`-driven scheduler tests will reuse.
    #[test]
    fn end_to_end_advance_inject_observe_wakeup() {
        let clock = MockClock::new(0);
        let irq = MockIrqSource::new();

        // A task arms a wakeup three ticks out.
        let task_id: TaskId = 42;
        let now = clock.now();
        let deadline = now.checked_add(3).expect("no overflow on small seed");
        clock.enqueue_wakeup(deadline, task_id);
        assert_eq!(clock.pending_wakeups(), 1);

        // Two simulated timer ticks land — task is not yet due.
        for _ in 0..2 {
            irq.inject_timer();
            clock.tick();
            irq.ack_timer();
            let drained = clock.drain_expired(clock.now());
            assert!(
                drained.is_empty(),
                "task should not wake before deadline; drained={:?}",
                drained
            );
        }
        assert_eq!(irq.ack_count(), 2);
        assert_eq!(irq.pending_timers(), 0);

        // Third tick crosses the deadline → drain returns the task id.
        irq.inject_timer();
        clock.tick();
        irq.ack_timer();
        let drained = clock.drain_expired(clock.now());
        assert_eq!(drained, alloc::vec![task_id]);
        assert_eq!(clock.pending_wakeups(), 0);
        assert_eq!(irq.ack_count(), 3);
        assert_eq!(irq.pending_timers(), 0);
    }
}
