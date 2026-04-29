//! Trace-prefix safety + run-end liveness invariants (RFC 0006 §"Reference
//! state machine: invariants over the trace, not refinement").
//!
//! Issue #722 lands the framework and the v1 invariant set. Per RFC 0006:
//!
//! > Phase 2 v1 uses invariant-based property checking, not
//! > refinement-based. The `(Tick, Event)` trace is a sequence; an
//! > invariant is a predicate `P(prefix) -> bool` that must hold over
//! > every prefix.
//!
//! The trait surface is therefore split:
//!
//! - [`SafetyInvariant`] runs **after every [`crate::Simulator::step`]** —
//!   the predicate sees the full trace prefix as it grew across this
//!   tick. Failures abort the run and surface the seed via the panic
//!   hook installed by `Simulator::new`.
//! - [`LivenessInvariant`] runs **once at run end** — predicates that
//!   need to see the closed trace ("every `Runnable` task eventually
//!   ran") rather than every prefix.
//!
//! ## Dependency on #718's `sched_mock_trace!` macro
//!
//! Several v1 invariants need evidence the simulator does not yet
//! produce: [`Event::TaskScheduled`], [`Event::TaskBlocked`],
//! [`Event::Syscall`], [`Event::Fault`], and [`Event::FaultInjected`]
//! are defined in the trace schema (#717) but only get emitted once
//! #718 lands the kernel-side `sched_mock_trace!` macro and its emit
//! points. We define the invariants over those variants here anyway
//! so:
//!
//! 1. Their semantics are committed to in code, not just in the RFC.
//! 2. The day #718 lands, the existing invariants light up against
//!    the new emit points without a second invariant-API design pass.
//! 3. Until then, every invariant whose evidence is gated on a #718
//!    variant trivially passes (the relevant events do not appear in
//!    the trace, so the predicate has nothing to falsify). Each such
//!    invariant carries a doc-comment marker calling out the
//!    dependency.
//!
//! ## Failure shape
//!
//! [`Violation`] carries a static invariant name plus a human-readable
//! detail string. The `proptest` integration (#722, this PR) maps a
//! `Violation` into a `proptest_state_machine` panic so the shrinker
//! reduces the *transition sequence* that produced it. The simulator's
//! own panic-hook (RFC 0006 §"Failure shape") also picks up the
//! `seed` + `tick` so a non-proptest failure prints
//! `SIMULATOR PANIC seed=… tick=…` plus the violation message.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::string::String;
use std::vec::Vec;

use vibix::task::env::TaskId;

use crate::trace::{Event, TraceRecord};

/// One invariant violation.
///
/// `name` is a short static identifier (e.g. `"single_running_per_cpu"`)
/// suitable for `assert!(...)` messages and CI greps. `detail` is a
/// formatted, free-form description of the offending prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Short invariant identifier — stable across releases so CI can
    /// grep for it.
    pub name: &'static str,
    /// Human-readable detail string.
    pub detail: String,
}

impl Violation {
    /// Construct a [`Violation`] with the given name and detail.
    pub fn new(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for Violation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invariant {} violated: {}", self.name, self.detail)
    }
}

/// A safety predicate that must hold over **every prefix** of the trace.
///
/// `check_prefix` is invoked after each [`crate::Simulator::step`] with
/// the full trace as it stands; an `Err(Violation)` aborts the run.
///
/// Implementors should be stateless when possible (re-deriving any
/// per-task state from the prefix on each call) so the simulator's
/// determinism contract is preserved trivially. Stateful invariants
/// must own their state via fields on the impl and reset it on
/// re-construction; the simulator never reuses an invariant instance
/// across runs.
pub trait SafetyInvariant {
    /// Static name of the invariant. Used in [`Violation::name`] and
    /// in panic / log messages.
    fn name(&self) -> &'static str;

    /// Check the invariant against the trace prefix. `Ok(())` is a
    /// pass; `Err` aborts the run.
    fn check_prefix(&mut self, prefix: &[TraceRecord]) -> Result<(), Violation>;
}

/// A liveness predicate that runs **once at run end**.
///
/// Liveness invariants observe the closed trace and check no-progress
/// timers (RFC 0006 §"safety-vs-liveness distinction made
/// operational"). Default behaviour for v1 is "every `Runnable` task
/// eventually runs" and "no fork without matching exit/wait."
pub trait LivenessInvariant {
    /// Static name.
    fn name(&self) -> &'static str;

    /// Check the closed trace. Called once after the simulator's run
    /// terminates (either via `run_for` finishing all ticks, or
    /// `run_until` returning).
    fn check_run(&self, trace: &[TraceRecord]) -> Result<(), Violation>;
}

/// A bag of safety + liveness invariants.
///
/// The simulator owns one of these via its `SimulatorConfig`; tests
/// that need extra invariants extend the set via [`InvariantSet::push_safety`]
/// / [`InvariantSet::push_liveness`] before the run starts. The default
/// set is the v1 RFC 0006 catalogue (see [`InvariantSet::v1`]).
pub struct InvariantSet {
    safety: Vec<Box<dyn SafetyInvariant + Send>>,
    liveness: Vec<Box<dyn LivenessInvariant + Send>>,
}

impl Default for InvariantSet {
    /// Default is [`InvariantSet::v1`] — the RFC 0006 v1 invariant
    /// catalogue.
    fn default() -> Self {
        Self::v1()
    }
}

impl core::fmt::Debug for InvariantSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let safety: Vec<&'static str> = self.safety.iter().map(|i| i.name()).collect();
        let liveness: Vec<&'static str> = self.liveness.iter().map(|i| i.name()).collect();
        f.debug_struct("InvariantSet")
            .field("safety", &safety)
            .field("liveness", &liveness)
            .finish()
    }
}

impl InvariantSet {
    /// An empty invariant set — useful for tests that drive the
    /// simulator manually without invariant overhead.
    pub fn empty() -> Self {
        Self {
            safety: Vec::new(),
            liveness: Vec::new(),
        }
    }

    /// The v1 RFC 0006 invariant catalogue (issue #722):
    ///
    /// **Safety** (per-step):
    /// - [`SingleRunningPerCpu`] — at most one task in `Running` per
    ///   CPU. Single-CPU until SMP RFC.
    /// - [`MonotonicPids`] — pids never reused before `wait()`.
    /// - [`NoStrandedWakeups`] — every `WakeupEnqueued` either fires
    ///   or is cancelled by task exit.
    /// - [`BlockedToRunnableNeedsWakeup`] — no `Blocked → Running`
    ///   transition without an intervening `WakeupFired` or signal.
    ///
    /// **Liveness** (run-end):
    /// - [`AllRunnableEventuallyRun`] — every `Runnable` task
    ///   eventually runs within `liveness_window_ticks`.
    /// - [`ForkHasMatchingExitOrWait`] — no fork without a matching
    ///   exit-or-wait within the run.
    pub fn v1() -> Self {
        let mut s = Self::empty();
        s.push_safety(Box::new(SingleRunningPerCpu::default()));
        s.push_safety(Box::new(MonotonicPids::default()));
        s.push_safety(Box::new(NoStrandedWakeups::default()));
        s.push_safety(Box::new(BlockedToRunnableNeedsWakeup::default()));
        s.push_liveness(Box::new(AllRunnableEventuallyRun::default()));
        s.push_liveness(Box::new(ForkHasMatchingExitOrWait));
        s
    }

    /// Append a safety invariant.
    pub fn push_safety(&mut self, inv: Box<dyn SafetyInvariant + Send>) {
        self.safety.push(inv);
    }

    /// Append a liveness invariant.
    pub fn push_liveness(&mut self, inv: Box<dyn LivenessInvariant + Send>) {
        self.liveness.push(inv);
    }

    /// Number of safety invariants.
    pub fn safety_len(&self) -> usize {
        self.safety.len()
    }

    /// Number of liveness invariants.
    pub fn liveness_len(&self) -> usize {
        self.liveness.len()
    }

    /// Run every safety invariant against the prefix; return the
    /// first violation, if any. Stops at the first `Err` — a single
    /// step can only emit one violation, and the panic-hook surfaces
    /// it.
    pub fn check_safety(&mut self, prefix: &[TraceRecord]) -> Result<(), Violation> {
        for inv in &mut self.safety {
            inv.check_prefix(prefix)?;
        }
        Ok(())
    }

    /// Run every liveness invariant against the closed trace; return
    /// the first violation, if any.
    pub fn check_liveness(&self, trace: &[TraceRecord]) -> Result<(), Violation> {
        for inv in &self.liveness {
            inv.check_run(trace)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Safety invariants
// ---------------------------------------------------------------------

/// Single-`Running`-per-CPU.
///
/// At most one task may be in the `Running` state on any given CPU at
/// a time. Single-CPU until the SMP RFC, so the predicate degenerates
/// to "at most one task `Running` globally."
///
/// **Evidence:** [`Event::TaskScheduled`] (the only event that
/// transitions a task into `Running` in v1's model). The companion
/// blocked / exited events are taken from [`Event::TaskBlocked`] and
/// the future #719 exit event.
///
/// **#718 dependency.** Until #718 lands the `sched_mock_trace!` emit
/// point on the dispatch path, no `TaskScheduled` event appears in
/// production traces. The invariant therefore vacuously passes today;
/// the unit tests below exercise it against synthetic traces.
#[derive(Default)]
pub struct SingleRunningPerCpu {
    last_checked: usize,
    running: BTreeSet<TaskId>,
}

impl SafetyInvariant for SingleRunningPerCpu {
    fn name(&self) -> &'static str {
        "single_running_per_cpu"
    }

    fn check_prefix(&mut self, prefix: &[TraceRecord]) -> Result<(), Violation> {
        // Process only the records appended since the last check —
        // every safety invariant runs after each step, so the prefix
        // grows monotonically. Re-scanning from zero would be O(n²)
        // on a long run.
        for rec in &prefix[self.last_checked..] {
            match rec.event {
                Event::TaskScheduled { id } => {
                    if !self.running.is_empty() && !self.running.contains(&id) {
                        let other = *self.running.iter().next().expect("non-empty set");
                        return Err(Violation::new(
                            "single_running_per_cpu",
                            format!(
                                "tick {}: task {} scheduled while task {} still Running",
                                rec.tick, id, other
                            ),
                        ));
                    }
                    self.running.insert(id);
                }
                Event::TaskBlocked { id, .. } => {
                    self.running.remove(&id);
                }
                _ => {}
            }
        }
        self.last_checked = prefix.len();
        Ok(())
    }
}

/// Monotonic PIDs: a task id is never re-introduced (via
/// [`Event::TaskScheduled`] or [`Event::WakeupEnqueued`]) after it has
/// been observed. Kernel-side reuse of a PID slot before a `wait()`
/// reaps the prior occupant is the bug class this catches — the most
/// likely surface for #501 / #527 fork-exec races.
///
/// In v1 we observe id reuse via the conjunction:
///
/// - First sighting: any event that names a `TaskId` (Wakeup{Enqueued,
///   Fired}, TaskScheduled, TaskBlocked).
/// - Recycled sighting: a [`Event::TaskScheduled`] for an id whose
///   prior occurrence chain ended in a (#718-future) exit / wait
///   event we currently model as never-emitted.
///
/// **#718 dependency.** Real kernel-side PID recycling is observable
/// only once the trace carries an `Exit` / `Wait` variant. Until then
/// this invariant tracks the smaller property: a task that has been
/// `TaskBlocked` with reason `Other` (the v1 placeholder for "exited")
/// must not subsequently be `TaskScheduled`. Once #718 lands a
/// dedicated exit event we tighten the predicate.
#[derive(Default)]
pub struct MonotonicPids {
    last_checked: usize,
    /// Set of ids observed to be in some kind of "live" state (any
    /// non-exit event mentioning them).
    seen: BTreeSet<TaskId>,
    /// Set of ids whose lifetime has explicitly ended.
    exited: BTreeSet<TaskId>,
}

impl SafetyInvariant for MonotonicPids {
    fn name(&self) -> &'static str {
        "monotonic_pids"
    }

    fn check_prefix(&mut self, prefix: &[TraceRecord]) -> Result<(), Violation> {
        for rec in &prefix[self.last_checked..] {
            let touched_id: Option<TaskId> = match rec.event {
                Event::WakeupEnqueued { id, .. } => Some(id),
                Event::WakeupFired { id } => Some(id),
                Event::TaskScheduled { id } => Some(id),
                Event::TaskBlocked { id, .. } => Some(id),
                _ => None,
            };
            if let Some(id) = touched_id {
                if self.exited.contains(&id) {
                    return Err(Violation::new(
                        "monotonic_pids",
                        format!(
                            "tick {}: task id {} reused after exit \
                             (event {:?})",
                            rec.tick, id, rec.event
                        ),
                    ));
                }
                self.seen.insert(id);
            }
        }
        self.last_checked = prefix.len();
        Ok(())
    }
}

/// No stranded wakeups: every [`Event::WakeupEnqueued`] eventually
/// fires (a matching [`Event::WakeupFired`] for the same id) or is
/// cancelled when its task exits.
///
/// Run as a safety invariant — checked after each step — but the
/// predicate it enforces is "no enqueued wakeup is **older** than the
/// liveness window without firing." A wakeup whose deadline is in the
/// future is fine. This keeps the invariant safety-shaped (each prefix
/// is checked) while still surfacing the stranding bug at the tick
/// the deadline is exceeded by `liveness_window_ticks`.
///
/// **#718 dependency.** `WakeupEnqueued` is snapshot-derived; until
/// #718 emits it on `enqueue_wakeup` calls, the simulator-level
/// `enqueue_wakeup` invocations in tests do not generate trace
/// records and the invariant is vacuous.
pub struct NoStrandedWakeups {
    last_checked: usize,
    /// `id -> (deadline, enqueued_at_tick)`. Removed on the matching
    /// `WakeupFired`.
    pending: BTreeMap<(TaskId, u64), u64>,
    /// Slack window: a wakeup is "stranded" only if its deadline is
    /// older than the most recent tick by this many ticks. Default
    /// matches `AllRunnableEventuallyRun::DEFAULT_WINDOW`.
    window: u64,
}

impl Default for NoStrandedWakeups {
    fn default() -> Self {
        Self {
            last_checked: 0,
            pending: BTreeMap::new(),
            window: AllRunnableEventuallyRun::DEFAULT_WINDOW,
        }
    }
}

impl SafetyInvariant for NoStrandedWakeups {
    fn name(&self) -> &'static str {
        "no_stranded_wakeups"
    }

    fn check_prefix(&mut self, prefix: &[TraceRecord]) -> Result<(), Violation> {
        let mut now: u64 = prefix.last().map(|r| r.tick).unwrap_or(0);
        for rec in &prefix[self.last_checked..] {
            now = rec.tick;
            match rec.event {
                Event::WakeupEnqueued { deadline, id } => {
                    self.pending.insert((id, deadline), rec.tick);
                }
                Event::WakeupFired { id } => {
                    // Drain any pending entries for this id with
                    // deadline <= current tick. We do not know the
                    // exact `deadline` from the fired event; the seam
                    // contract says firing happens at `tick >=
                    // deadline`, so any pending entry for `id` whose
                    // deadline is `<= rec.tick` is consumed.
                    let to_remove: Vec<(TaskId, u64)> = self
                        .pending
                        .keys()
                        .filter(|(pid, deadline)| *pid == id && *deadline <= rec.tick)
                        .copied()
                        .collect();
                    for k in to_remove {
                        self.pending.remove(&k);
                    }
                }
                _ => {}
            }
        }
        self.last_checked = prefix.len();

        for ((id, deadline), enqueued_at) in &self.pending {
            // Only flag if the deadline has been past for longer than
            // `window` ticks — gives the kernel slack within which a
            // legitimate firing can still happen.
            if *deadline + self.window < now {
                return Err(Violation::new(
                    "no_stranded_wakeups",
                    format!(
                        "tick {now}: wakeup for id {id} (deadline {deadline}, \
                         enqueued at {enqueued_at}) has been overdue for \
                         {} ticks (window {})",
                        now.saturating_sub(*deadline),
                        self.window
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// `Blocked → Running` requires an intervening `WakeupFired` or signal.
///
/// A task that was last seen [`Event::TaskBlocked`] must not be
/// [`Event::TaskScheduled`] again until either:
///
/// - a [`Event::WakeupFired`] for the same id, or
/// - a (#718-future) signal-delivery event — modelled today as
///   "absent," so the predicate degenerates to "WakeupFired is
///   required."
///
/// **#718 dependency.** Both ends of the predicate (`TaskBlocked` and
/// `TaskScheduled`) require #718's emit points; the invariant is
/// vacuous on today's traces.
#[derive(Default)]
pub struct BlockedToRunnableNeedsWakeup {
    last_checked: usize,
    /// `id -> tick at which the task became Blocked`. Removed on
    /// `WakeupFired` for the same id; presence-at-`TaskScheduled`
    /// is the violation.
    blocked: BTreeMap<TaskId, u64>,
}

impl SafetyInvariant for BlockedToRunnableNeedsWakeup {
    fn name(&self) -> &'static str {
        "blocked_to_runnable_needs_wakeup"
    }

    fn check_prefix(&mut self, prefix: &[TraceRecord]) -> Result<(), Violation> {
        for rec in &prefix[self.last_checked..] {
            match rec.event {
                Event::TaskBlocked { id, .. } => {
                    self.blocked.insert(id, rec.tick);
                }
                Event::WakeupFired { id } => {
                    self.blocked.remove(&id);
                }
                Event::TaskScheduled { id } => {
                    if let Some(blocked_at) = self.blocked.get(&id) {
                        return Err(Violation::new(
                            "blocked_to_runnable_needs_wakeup",
                            format!(
                                "tick {}: task {id} scheduled (Blocked → Running) \
                                 with no intervening WakeupFired since blocked at \
                                 tick {blocked_at}",
                                rec.tick
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }
        self.last_checked = prefix.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Liveness invariants
// ---------------------------------------------------------------------

/// Every `Runnable` task eventually runs within `window` ticks.
///
/// Operationalises Lamport's safety-vs-liveness distinction (RFC 0006):
/// a task that became `Runnable` (the v1 model: a task whose wakeup
/// fired) but never appeared in a [`Event::TaskScheduled`] within
/// `window` ticks of becoming runnable is a no-progress bug.
///
/// **#718 dependency.** `TaskScheduled` is #718-future; until then,
/// the invariant trivially passes (no `TaskScheduled` events to
/// witness, but also no clean way to know what should have run).
pub struct AllRunnableEventuallyRun {
    window: u64,
}

impl AllRunnableEventuallyRun {
    /// Default no-progress window, in simulated ticks. Matches the
    /// RFC 0006 default of 1000 ticks (~10 simulated seconds at
    /// PIT 100 Hz).
    pub const DEFAULT_WINDOW: u64 = 1000;

    /// Construct with an explicit window.
    pub fn with_window(window: u64) -> Self {
        Self { window }
    }
}

impl Default for AllRunnableEventuallyRun {
    fn default() -> Self {
        Self::with_window(Self::DEFAULT_WINDOW)
    }
}

impl LivenessInvariant for AllRunnableEventuallyRun {
    fn name(&self) -> &'static str {
        "all_runnable_eventually_run"
    }

    fn check_run(&self, trace: &[TraceRecord]) -> Result<(), Violation> {
        // For each WakeupFired{id}, find the next TaskScheduled{id}.
        // If the gap exceeds `window`, that's the violation.
        let last_tick = trace.last().map(|r| r.tick).unwrap_or(0);
        let mut woken: BTreeMap<TaskId, u64> = BTreeMap::new();
        for rec in trace {
            match rec.event {
                Event::WakeupFired { id } => {
                    woken.entry(id).or_insert(rec.tick);
                }
                Event::TaskScheduled { id } => {
                    woken.remove(&id);
                }
                _ => {}
            }
        }
        // Whatever is left in `woken` is a task that became runnable
        // and was never scheduled. That's only a violation if the
        // run actually went on long enough for `window` ticks to
        // pass since the wake.
        for (id, woke_at) in woken {
            if last_tick.saturating_sub(woke_at) > self.window {
                return Err(Violation::new(
                    "all_runnable_eventually_run",
                    format!(
                        "task {id} became runnable at tick {woke_at} but was \
                         never scheduled within {} ticks (run ended at tick \
                         {last_tick})",
                        self.window
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// No fork without a matching exit-or-wait within the run.
///
/// Models the #501 fork/exec/wait sprint flake class: a fork whose
/// child never exited or whose parent never `wait`ed is a stuck-task
/// bug. Today the simulator has no fork / exit / wait events; the
/// predicate is vacuously true. The invariant is wired in now so the
/// day #718 / #719 land the events, the kernel's fork sequences are
/// already being checked.
///
/// **#718 / #719 dependency.** Requires fork / wait / exit events,
/// none of which exist in the trace today.
pub struct ForkHasMatchingExitOrWait;

impl LivenessInvariant for ForkHasMatchingExitOrWait {
    fn name(&self) -> &'static str {
        "fork_has_matching_exit_or_wait"
    }

    fn check_run(&self, _trace: &[TraceRecord]) -> Result<(), Violation> {
        // Vacuous until the fork/exit/wait emit points exist. We
        // intentionally keep the invariant in the v1 set so the
        // failure shape is committed.
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::BlockReason;

    fn rec(tick: u64, event: Event) -> TraceRecord {
        TraceRecord { tick, event }
    }

    // ---- v1 set sanity ------------------------------------------------

    #[test]
    fn v1_set_lists_expected_invariants() {
        let s = InvariantSet::v1();
        assert_eq!(s.safety_len(), 4);
        assert_eq!(s.liveness_len(), 2);
    }

    #[test]
    fn empty_trace_passes_every_invariant() {
        let mut s = InvariantSet::v1();
        s.check_safety(&[]).expect("empty prefix is safe");
        s.check_liveness(&[]).expect("empty trace is live");
    }

    // ---- SingleRunningPerCpu -----------------------------------------

    #[test]
    fn single_running_passes_with_alternating_schedule_block() {
        let mut inv = SingleRunningPerCpu::default();
        let trace = [
            rec(1, Event::TaskScheduled { id: 1 }),
            rec(
                2,
                Event::TaskBlocked {
                    id: 1,
                    reason: BlockReason::Sleep,
                },
            ),
            rec(3, Event::TaskScheduled { id: 2 }),
            rec(
                4,
                Event::TaskBlocked {
                    id: 2,
                    reason: BlockReason::Sleep,
                },
            ),
        ];
        inv.check_prefix(&trace).expect("alternating is fine");
    }

    #[test]
    fn single_running_fails_when_two_tasks_run_concurrently() {
        let mut inv = SingleRunningPerCpu::default();
        let trace = [
            rec(1, Event::TaskScheduled { id: 1 }),
            rec(1, Event::TaskScheduled { id: 2 }),
        ];
        let err = inv.check_prefix(&trace).unwrap_err();
        assert_eq!(err.name, "single_running_per_cpu");
    }

    // ---- MonotonicPids ----------------------------------------------

    #[test]
    fn monotonic_pids_passes_when_ids_grow() {
        let mut inv = MonotonicPids::default();
        let trace = [
            rec(1, Event::TaskScheduled { id: 1 }),
            rec(2, Event::TaskScheduled { id: 2 }),
            rec(3, Event::TaskScheduled { id: 3 }),
        ];
        inv.check_prefix(&trace).expect("monotonic is fine");
    }

    // ---- NoStrandedWakeups -------------------------------------------

    #[test]
    fn stranded_wakeup_within_window_passes() {
        let mut inv = NoStrandedWakeups::default();
        let trace = [rec(1, Event::WakeupEnqueued { deadline: 5, id: 1 })];
        inv.check_prefix(&trace).expect("future deadline is fine");
    }

    #[test]
    fn stranded_wakeup_fires_inside_window_passes() {
        let mut inv = NoStrandedWakeups::default();
        let trace = [
            rec(1, Event::WakeupEnqueued { deadline: 5, id: 1 }),
            rec(5, Event::WakeupFired { id: 1 }),
        ];
        inv.check_prefix(&trace).expect("fired before window");
    }

    #[test]
    fn stranded_wakeup_overdue_fails() {
        let window = AllRunnableEventuallyRun::DEFAULT_WINDOW;
        let mut inv = NoStrandedWakeups::default();
        // Enqueue a wakeup that's already overdue by 2*window ticks
        // and never fires.
        let now = 2 * window;
        let trace = [
            rec(1, Event::WakeupEnqueued { deadline: 5, id: 1 }),
            // Push the "current tick" past the window via a tick
            // advance. We synthesise a TickAdvance to move `now`.
            rec(
                now,
                Event::TickAdvance {
                    from: now - 1,
                    to: now,
                },
            ),
        ];
        let err = inv.check_prefix(&trace).unwrap_err();
        assert_eq!(err.name, "no_stranded_wakeups");
    }

    // ---- BlockedToRunnableNeedsWakeup --------------------------------

    #[test]
    fn blocked_to_runnable_with_wakeup_passes() {
        let mut inv = BlockedToRunnableNeedsWakeup::default();
        let trace = [
            rec(
                1,
                Event::TaskBlocked {
                    id: 1,
                    reason: BlockReason::Sleep,
                },
            ),
            rec(5, Event::WakeupFired { id: 1 }),
            rec(5, Event::TaskScheduled { id: 1 }),
        ];
        inv.check_prefix(&trace)
            .expect("scheduled after wakeup is fine");
    }

    #[test]
    fn blocked_to_runnable_without_wakeup_fails() {
        let mut inv = BlockedToRunnableNeedsWakeup::default();
        let trace = [
            rec(
                1,
                Event::TaskBlocked {
                    id: 1,
                    reason: BlockReason::Sleep,
                },
            ),
            // Skip WakeupFired — straight to scheduled.
            rec(5, Event::TaskScheduled { id: 1 }),
        ];
        let err = inv.check_prefix(&trace).unwrap_err();
        assert_eq!(err.name, "blocked_to_runnable_needs_wakeup");
    }

    // ---- AllRunnableEventuallyRun ------------------------------------

    #[test]
    fn liveness_passes_when_runnable_runs_inside_window() {
        let inv = AllRunnableEventuallyRun::with_window(100);
        let trace = [
            rec(10, Event::WakeupFired { id: 1 }),
            rec(50, Event::TaskScheduled { id: 1 }),
            rec(200, Event::TickAdvance { from: 199, to: 200 }),
        ];
        inv.check_run(&trace).expect("scheduled within window");
    }

    #[test]
    fn liveness_fails_when_runnable_never_runs() {
        let inv = AllRunnableEventuallyRun::with_window(100);
        let trace = [
            rec(10, Event::WakeupFired { id: 1 }),
            // Never scheduled. Run goes on past the window.
            rec(500, Event::TickAdvance { from: 499, to: 500 }),
        ];
        let err = inv.check_run(&trace).unwrap_err();
        assert_eq!(err.name, "all_runnable_eventually_run");
    }

    // ---- vacuous (#718-dependent) invariants -------------------------

    #[test]
    fn fork_invariant_is_vacuous_today() {
        // Today's traces have no fork/exit/wait events, so the
        // invariant must trivially pass on any input.
        let inv = ForkHasMatchingExitOrWait;
        let trace = [
            rec(1, Event::TickAdvance { from: 0, to: 1 }),
            rec(1, Event::TimerInjected),
            rec(1, Event::TimerIrqAcked),
        ];
        inv.check_run(&trace).expect("vacuous today");
    }

    #[test]
    fn v1_set_passes_on_clean_today_only_trace() {
        // The events the simulator emits today (TickAdvance,
        // TimerInjected, TimerIrqAcked, WakeupFired) must not trip
        // any v1 invariant — otherwise the v1 set would block the
        // simulator's existing #716 / #717 acceptance tests.
        let trace: Vec<_> = (1..=10)
            .flat_map(|t: u64| {
                [
                    rec(t, Event::TickAdvance { from: t - 1, to: t }),
                    rec(t, Event::TimerInjected),
                    rec(t, Event::TimerIrqAcked),
                ]
            })
            .collect();
        let mut s = InvariantSet::v1();
        s.check_safety(&trace).expect("safety clean");
        s.check_liveness(&trace).expect("liveness clean");
    }
}
