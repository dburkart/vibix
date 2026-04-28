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
        crate::arch::x86_64::apic::lapic_eoi();
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
