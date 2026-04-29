//! Seed minimizer — tick-window bisect + FaultPlan delta-debug
//! (RFC 0006 §"Seed minimization and trace shrinking", issue #720).
//!
//! Turns a 30-minute failing repro into a sub-minute one by trimming
//! everything irrelevant from a `(seed, FaultPlan, T_max)` tuple while
//! preserving the property "this configuration still reproduces the
//! failure."
//!
//! # Two stages
//!
//! 1. **Tick-window binary search.** Given an upper bound `T_max`, find
//!    the smallest `T_hi <= T_max` such that running the simulator for
//!    `T_hi` ticks still reproduces. Then find the largest `T_lo` such
//!    that dropping every fault-plan entry with `tick < T_lo` (i.e.
//!    "skipping" the leading window) still reproduces. The output is
//!    a half-open interval `[T_lo, T_hi)` that covers the failure
//!    causally and nothing more.
//!
//! 2. **`ddmin` over the FaultPlan.** Standard Zeller-Hildebrandt
//!    1-minimal delta debugging on the (already tick-clipped) entry
//!    list: try dropping every contiguous chunk of size `n = len/g`
//!    (granularity `g` doubles every full sweep that finds nothing),
//!    keep any drop that still reproduces, restart at the new size.
//!    Terminates at a `1-minimal` plan: removing any single entry
//!    breaks reproduction.
//!
//! # Operation bound
//!
//! Stage 1: `O(log T_max)` reproduction calls (two binary searches).
//! Stage 2: `O(|plan|^2)` reproduction calls in the worst case, the
//! standard ddmin bound.
//!
//! Total: **`O(log T_max) + O(|plan|^2)`** — documented and asserted
//! by the unit tests below via a call counter.
//!
//! # Determinism
//!
//! The `Reproducer` callback is treated as a pure function of
//! `(seed, plan, tick_window)`. Every reproduction attempt re-runs the
//! simulator from a fresh thread (because [`crate::Simulator::new`]'s
//! kernel-side `install_sim_env` panics on a second call to the same
//! thread). The minimizer itself does not consume any RNG bytes — its
//! search trajectory is a pure function of the input.

use std::string::String;
use std::vec::Vec;

use crate::fault_plan::{FaultEvent, FaultPlan};

/// Closed-on-the-left, open-on-the-right window of ticks the simulator
/// must execute for the failure to reproduce.
///
/// The lower bound `lo` filters the [`FaultPlan`]: entries with
/// `tick < lo` are dropped before the simulator consumes them. The
/// upper bound `hi` is the number of ticks the simulator runs for —
/// `Simulator::run_for(hi)`. A failure that reproduces under
/// `TickWindow { lo: 0, hi: T_max }` is the input the minimizer
/// starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickWindow {
    /// Minimum tick at which fault-plan events remain enabled. Events
    /// with `tick < lo` are filtered out before reproduction.
    pub lo: u64,
    /// Number of `Simulator::step` calls made during reproduction
    /// (i.e. the simulator's `run_for(hi)` argument).
    pub hi: u64,
}

impl TickWindow {
    /// Construct a window covering `[0, hi)`.
    pub const fn full(hi: u64) -> Self {
        Self { lo: 0, hi }
    }
}

/// Result of running the two-stage minimizer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinimizeOutput {
    /// Master seed (unchanged from input — the minimizer never tries
    /// alternative seeds; that would be a *different* repro).
    pub seed: u64,
    /// Minimized fault plan: `1-minimal` w.r.t. `Reproducer`.
    pub plan: FaultPlan,
    /// Minimized tick window. `tick_window.hi` is the smallest
    /// `Simulator::run_for(N)` that still reproduces; `tick_window.lo`
    /// is the largest leading-tick prefix that can be skipped.
    pub tick_window: TickWindow,
    /// Number of times [`Reproducer::reproduces`] was called during
    /// minimization. Used by tests to assert the operation bound.
    pub calls: u64,
}

/// Callback invoked by the minimizer to decide whether a candidate
/// `(seed, plan, tick_window)` triple still reproduces the failure.
///
/// Implementations that drive the simulator typically:
///
/// 1. Construct a fresh thread (because `Simulator::new`'s
///    `install_sim_env` is per-thread and panics on a second call).
/// 2. Catch panics with `std::panic::catch_unwind` and treat a panic
///    as "reproduces" for failure modes that surface as `panic!`.
///
/// The trait is single-method to keep adapters trivial; the
/// [`closure_reproducer`] helper wraps any `FnMut` into a
/// `Reproducer`.
pub trait Reproducer {
    /// Returns `true` if running the simulator with the given seed,
    /// plan (already tick-clipped), and `tick_window.hi` ticks still
    /// reproduces the failure under test.
    fn reproduces(&mut self, seed: u64, plan: &FaultPlan, tick_window: TickWindow) -> bool;
}

/// Wrap an `FnMut` into a [`Reproducer`].
pub fn closure_reproducer<F>(f: F) -> ClosureReproducer<F>
where
    F: FnMut(u64, &FaultPlan, TickWindow) -> bool,
{
    ClosureReproducer { f }
}

/// `Reproducer` impl backed by a closure. Constructed via
/// [`closure_reproducer`].
pub struct ClosureReproducer<F> {
    f: F,
}

impl<F> Reproducer for ClosureReproducer<F>
where
    F: FnMut(u64, &FaultPlan, TickWindow) -> bool,
{
    fn reproduces(&mut self, seed: u64, plan: &FaultPlan, tick_window: TickWindow) -> bool {
        (self.f)(seed, plan, tick_window)
    }
}

/// Filter a [`FaultPlan`] to entries with `tick >= lo`.
fn clip_plan_lo(plan: &FaultPlan, lo: u64) -> FaultPlan {
    let kept: Vec<(u64, FaultEvent)> = plan
        .entries()
        .iter()
        .filter(|(t, _)| *t >= lo)
        .copied()
        .collect();
    FaultPlan::from_entries(kept)
}

/// Counter-wrapped `Reproducer` so the minimizer can report how many
/// reproduction attempts it spent — both for diagnostics and for the
/// unit tests' operation-bound assertions.
struct Counted<'r, R: Reproducer + ?Sized> {
    inner: &'r mut R,
    calls: u64,
}

impl<R: Reproducer + ?Sized> Counted<'_, R> {
    fn check(&mut self, seed: u64, plan: &FaultPlan, window: TickWindow) -> bool {
        self.calls += 1;
        self.inner.reproduces(seed, plan, window)
    }
}

/// Run stage 1 (tick-window bisect) then stage 2 (ddmin over the plan)
/// against `reproducer`. The input is required to already reproduce
/// — the minimizer asserts this with one initial sanity call and
/// returns an error if it does not.
///
/// Operation bound: `O(log tick_window.hi) + O(|plan|^2)`.
pub fn minimize<R: Reproducer + ?Sized>(
    reproducer: &mut R,
    seed: u64,
    plan: FaultPlan,
    tick_window: TickWindow,
) -> Result<MinimizeOutput, String> {
    let mut counted = Counted {
        inner: reproducer,
        calls: 0,
    };

    // Sanity: the input itself must reproduce. If it doesn't, the
    // user's predicate is wrong and ddmin would silently terminate
    // on the empty plan (every subset trivially "reproduces" because
    // none reproduce). Surface the error.
    if !counted.check(seed, &plan, tick_window) {
        return Err(String::from(
            "minimize: input (seed, plan, tick_window) does not reproduce the failure; \
             check the Reproducer predicate before retrying",
        ));
    }

    // Stage 1a: shrink `tick_window.hi`.
    let hi = bisect_tick_hi(&mut counted, seed, &plan, tick_window)?;
    let mut window = TickWindow {
        lo: tick_window.lo,
        hi,
    };

    // Stage 1b: grow `tick_window.lo`. Searches the largest prefix of
    // ticks that can be skipped (i.e. plan entries with tick < lo
    // dropped) without breaking reproduction.
    let lo = bisect_tick_lo(&mut counted, seed, &plan, window)?;
    window.lo = lo;

    // Apply the lower-bound clip to the plan so stage 2 only ddmin's
    // over the entries the bisect determined are still in scope.
    let clipped = clip_plan_lo(&plan, window.lo);

    // Stage 2: ddmin over the (clipped) plan's entries.
    let minimized = ddmin(&mut counted, seed, clipped, window)?;

    Ok(MinimizeOutput {
        seed,
        plan: minimized,
        tick_window: window,
        calls: counted.calls,
    })
}

/// Find the smallest `hi` in `[1, tick_window.hi]` such that
/// `(seed, plan, TickWindow { lo, hi })` still reproduces.
fn bisect_tick_hi<R: Reproducer + ?Sized>(
    counted: &mut Counted<'_, R>,
    seed: u64,
    plan: &FaultPlan,
    tick_window: TickWindow,
) -> Result<u64, String> {
    if tick_window.hi <= 1 {
        return Ok(tick_window.hi);
    }
    // Invariant: `lo` does not reproduce, `hi` reproduces. Both bounds
    // refer to the `hi` field of `TickWindow`. Start `lo = 0` (zero
    // ticks: the simulator never advances; cannot reproduce a fault
    // injected at any tick > 0) and `hi = tick_window.hi` (the
    // entry-sanity check already proved this reproduces).
    let mut lo = 0u64;
    let mut hi = tick_window.hi;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        let candidate = TickWindow {
            lo: tick_window.lo,
            hi: mid,
        };
        if counted.check(seed, plan, candidate) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Ok(hi)
}

/// Find the largest `lo` in `[0, tick_window.hi]` such that
/// `(seed, clip_plan_lo(plan, lo), TickWindow { lo, hi })` still
/// reproduces.
fn bisect_tick_lo<R: Reproducer + ?Sized>(
    counted: &mut Counted<'_, R>,
    seed: u64,
    plan: &FaultPlan,
    tick_window: TickWindow,
) -> Result<u64, String> {
    // Invariant: `lo` reproduces, `hi` does not. We search the largest
    // value that still reproduces. Start `lo = tick_window.lo` (the
    // sanity check proved this reproduces) and `hi = tick_window.hi + 1`
    // (clipping every entry trivially defeats reproduction unless the
    // failure does not depend on the plan at all — handled below).
    let mut lo = tick_window.lo;
    let mut hi = tick_window.hi.saturating_add(1);

    // Quick top-out check: if dropping every plan entry still
    // reproduces, the failure is independent of the plan; the lower
    // bound can be set right at `tick_window.hi` (no plan entries
    // remain in scope) and stage 2 will reduce the plan to empty.
    let drop_all = TickWindow {
        lo: hi,
        hi: tick_window.hi,
    };
    let drop_all_plan = clip_plan_lo(plan, drop_all.lo);
    if counted.check(seed, &drop_all_plan, drop_all) {
        return Ok(hi);
    }

    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        let candidate_window = TickWindow {
            lo: mid,
            hi: tick_window.hi,
        };
        let candidate_plan = clip_plan_lo(plan, mid);
        if counted.check(seed, &candidate_plan, candidate_window) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Zeller-Hildebrandt ddmin over the plan's entries. Returns a
/// 1-minimal plan: removing any single entry breaks reproduction.
fn ddmin<R: Reproducer + ?Sized>(
    counted: &mut Counted<'_, R>,
    seed: u64,
    plan: FaultPlan,
    window: TickWindow,
) -> Result<FaultPlan, String> {
    let mut entries: Vec<(u64, FaultEvent)> = plan.entries().to_vec();
    let mut granularity: usize = 2;

    // Outer loop: shrink while progress is being made. Standard ddmin
    // shape — split into `granularity` chunks, try removing each
    // chunk, then try removing each chunk's complement; if neither
    // helps, double the granularity.
    loop {
        let n = entries.len();
        if n < 2 {
            break;
        }
        let chunk_size = n.div_ceil(granularity);

        // Try removing each contiguous chunk (size = chunk_size).
        let mut reduced = false;
        let mut start = 0;
        while start < n {
            let end = (start + chunk_size).min(n);
            let mut candidate: Vec<(u64, FaultEvent)> = Vec::with_capacity(n - (end - start));
            candidate.extend_from_slice(&entries[..start]);
            candidate.extend_from_slice(&entries[end..]);
            let candidate_plan = FaultPlan::from_entries(candidate.clone());
            if counted.check(seed, &candidate_plan, window) {
                entries = candidate;
                reduced = true;
                break;
            }
            start = end;
        }

        if reduced {
            // Restart the sweep at the same granularity, but capped to
            // the new length so chunks remain non-empty.
            granularity = granularity.min(entries.len()).max(2);
            continue;
        }

        // Try removing each chunk's complement (i.e. keep only one
        // chunk). Equivalent to "is this chunk alone enough to
        // reproduce?" — the other half of the ddmin recurrence.
        let mut start = 0;
        while start < n {
            let end = (start + chunk_size).min(n);
            let candidate: Vec<(u64, FaultEvent)> = entries[start..end].to_vec();
            let candidate_plan = FaultPlan::from_entries(candidate.clone());
            if counted.check(seed, &candidate_plan, window) {
                entries = candidate;
                granularity = 2;
                reduced = true;
                break;
            }
            start = end;
        }
        if reduced {
            continue;
        }

        // No reduction at this granularity. Double it and retry; if
        // we've already reached granularity == n, we are 1-minimal.
        if granularity >= entries.len() {
            break;
        }
        granularity = (granularity * 2).min(entries.len());
    }

    Ok(FaultPlan::from_entries(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault_plan::FaultEvent;

    /// A `Reproducer` that "fails" iff the plan contains a specific
    /// trigger event at a specific tick within the window. Used by
    /// the unit tests below as a deterministic synthetic flake.
    struct TriggerOnEvent {
        trigger_tick: u64,
        trigger_event: FaultEvent,
    }

    impl Reproducer for TriggerOnEvent {
        fn reproduces(&mut self, _seed: u64, plan: &FaultPlan, window: TickWindow) -> bool {
            // The trigger must be within the active window:
            // - tick >= window.lo (otherwise clipped out by the caller,
            //   but this branch keeps the predicate independent of the
            //   caller doing the clipping)
            // - tick < window.hi (otherwise the simulator never gets
            //   far enough)
            // - and the entry must actually be present.
            plan.entries().iter().any(|(t, e)| {
                *t == self.trigger_tick
                    && *e == self.trigger_event
                    && *t >= window.lo
                    && *t < window.hi
            })
        }
    }

    fn noisy_plan_around(trigger_tick: u64, trigger: FaultEvent) -> FaultPlan {
        // Build a noisy plan with the trigger buried among unrelated
        // events at varied ticks. 20+ entries so ddmin has real work
        // to do.
        let entries = vec![
            (10, FaultEvent::SpuriousTimerIrq),
            (100, FaultEvent::TimerDrift { ticks: 1 }),
            (250, FaultEvent::WakeupReorder { within_tick: 1 }),
            (500, FaultEvent::SpuriousTimerIrq),
            (1000, FaultEvent::TimerDrift { ticks: 3 }),
            (2500, FaultEvent::WakeupReorder { within_tick: 2 }),
            (5000, FaultEvent::SpuriousTimerIrq),
            (7500, FaultEvent::TimerDrift { ticks: 1 }),
            (10000, FaultEvent::WakeupReorder { within_tick: 1 }),
            (11000, FaultEvent::SpuriousTimerIrq),
            (12000, FaultEvent::TimerDrift { ticks: 2 }),
            (trigger_tick, trigger),
            (12500, FaultEvent::WakeupReorder { within_tick: 1 }),
            (13000, FaultEvent::SpuriousTimerIrq),
            (15000, FaultEvent::TimerDrift { ticks: 1 }),
            (20000, FaultEvent::WakeupReorder { within_tick: 3 }),
            (25000, FaultEvent::SpuriousTimerIrq),
            (30000, FaultEvent::TimerDrift { ticks: 1 }),
            (40000, FaultEvent::WakeupReorder { within_tick: 1 }),
            (50000, FaultEvent::SpuriousTimerIrq),
        ];
        FaultPlan::from_entries(entries)
    }

    #[test]
    fn synthetic_flake_minimizes_to_single_event_plan() {
        // Acceptance: a synthetic flake "panic if SpuriousTimerIrq
        // lands in tick 12345" minimizes to a single-event plan.
        let trigger_tick = 12345;
        let trigger = FaultEvent::SpuriousTimerIrq;
        let plan = noisy_plan_around(trigger_tick, trigger);
        let initial_window = TickWindow::full(100_000);

        let mut rep = TriggerOnEvent {
            trigger_tick,
            trigger_event: trigger,
        };

        let out = minimize(&mut rep, 0xDEAD_BEEF, plan, initial_window).expect("minimize");

        // 1-minimal plan: exactly the trigger event at the trigger
        // tick, nothing else.
        assert_eq!(out.plan.entries(), &[(trigger_tick, trigger)]);

        // Tick window is tight: hi is just past the trigger,
        // lo is exactly at it (the largest skip that still includes
        // the trigger).
        assert_eq!(out.tick_window.lo, trigger_tick);
        assert_eq!(out.tick_window.hi, trigger_tick + 1);
        // Seed is unchanged.
        assert_eq!(out.seed, 0xDEAD_BEEF);
    }

    #[test]
    fn minimize_respects_operation_bound() {
        // Operation bound: `O(log T_max) + O(|plan|^2)` reproduction
        // calls. With T_max = 100_000 (log2 ≈ 17) and |plan| = 20,
        // a 5x slack accommodates ddmin's chunk-then-complement passes
        // while still flagging quadratic-blowup regressions.
        let trigger_tick = 12345;
        let trigger = FaultEvent::SpuriousTimerIrq;
        let plan = noisy_plan_around(trigger_tick, trigger);
        let initial_window = TickWindow::full(100_000);

        let mut rep = TriggerOnEvent {
            trigger_tick,
            trigger_event: trigger,
        };

        let out = minimize(&mut rep, 1, plan.clone(), initial_window).expect("minimize");

        let log_t = 64u64 - 100_000u64.leading_zeros() as u64; // ≈17
        let plan_sq = (plan.len() as u64).pow(2); // 400
        let bound = 5 * (log_t + plan_sq);
        assert!(
            out.calls <= bound,
            "minimize used {} calls, exceeds 5*(log T + |plan|^2) = {}",
            out.calls,
            bound,
        );
    }

    #[test]
    fn minimize_errors_when_input_does_not_reproduce() {
        // If the input itself doesn't reproduce, `minimize` must
        // surface the error rather than silently returning the empty
        // plan.
        let plan = FaultPlan::from_entries(vec![(1, FaultEvent::SpuriousTimerIrq)]);
        let mut rep = closure_reproducer(|_, _, _| false);
        let err = minimize(&mut rep, 0, plan, TickWindow::full(10)).unwrap_err();
        assert!(err.contains("does not reproduce"), "got: {err}");
    }

    #[test]
    fn ddmin_reduces_redundant_plan_to_minimal_subset() {
        // Predicate "reproduces iff plan contains both A and B".
        let a = (5, FaultEvent::SpuriousTimerIrq);
        let b = (15, FaultEvent::TimerDrift { ticks: 2 });
        let entries = vec![
            (1, FaultEvent::SpuriousTimerIrq),
            a,
            (10, FaultEvent::WakeupReorder { within_tick: 1 }),
            b,
            (20, FaultEvent::SpuriousTimerIrq),
            (25, FaultEvent::WakeupReorder { within_tick: 2 }),
        ];
        let plan = FaultPlan::from_entries(entries);

        let mut rep = closure_reproducer(move |_seed, plan: &FaultPlan, _w| {
            let has_a = plan.entries().contains(&a);
            let has_b = plan.entries().contains(&b);
            has_a && has_b
        });

        let out = minimize(&mut rep, 0, plan, TickWindow::full(100)).expect("minimize");
        // 1-minimal: dropping either entry breaks the predicate, so
        // both must remain.
        assert_eq!(out.plan.entries(), &[a, b]);
    }

    #[test]
    fn tick_window_lo_grows_when_failure_starts_late() {
        // Predicate "reproduces iff plan contains a SpuriousTimerIrq
        // at tick 50000". The failure does not depend on any earlier
        // tick — the lo bisect should grow lo all the way to 50000.
        let trigger_tick = 50_000;
        let trigger = FaultEvent::SpuriousTimerIrq;
        let plan = noisy_plan_around(trigger_tick, trigger);
        let mut rep = TriggerOnEvent {
            trigger_tick,
            trigger_event: trigger,
        };
        let out = minimize(&mut rep, 0, plan, TickWindow::full(100_000)).expect("minimize");
        assert_eq!(out.tick_window.lo, trigger_tick);
        assert_eq!(out.tick_window.hi, trigger_tick + 1);
        assert_eq!(out.plan.entries(), &[(trigger_tick, trigger)]);
    }

    #[test]
    fn empty_plan_input_returns_empty_output_when_failure_is_seed_only() {
        // A failure that depends only on the seed (no plan, no window
        // beyond a couple of ticks). The minimizer must terminate
        // quickly without trying to ddmin a nonexistent plan.
        let plan = FaultPlan::new();
        let mut rep = closure_reproducer(|_seed, _plan, w| w.hi >= 1);
        let out = minimize(&mut rep, 42, plan, TickWindow::full(1024)).expect("minimize");
        assert!(out.plan.is_empty());
        assert_eq!(out.tick_window.hi, 1);
    }

    #[test]
    fn clip_plan_lo_drops_strictly_lower_ticks() {
        let entries = vec![
            (0, FaultEvent::SpuriousTimerIrq),
            (5, FaultEvent::TimerDrift { ticks: 1 }),
            (10, FaultEvent::WakeupReorder { within_tick: 1 }),
        ];
        let plan = FaultPlan::from_entries(entries);
        let clipped = clip_plan_lo(&plan, 5);
        assert_eq!(clipped.len(), 2);
        assert_eq!(clipped.entries()[0].0, 5);
        assert_eq!(clipped.entries()[1].0, 10);
    }
}
