//! Regression test for [#501](https://github.com/dburkart/vibix/issues/501)
//! — fork/exec/wait flakiness modelled via the host-side DST simulator
//! (RFC 0006 §"Reproduction commitments", roadmap item 7, issue #721).
//!
//! # What this test reproduces
//!
//! The `fork_exec_wait_chain` scenario models the timing pattern of
//! init's `fork → execve → wait4` sequence at the seam (`MockClock`
//! `enqueue_wakeup` / `drain_expired`) granularity. A failing seed
//! captured here is the v1 simulator's analogue of the missed-wakeup
//! race documented in #501's body and follow-up updates:
//!
//! > kernel/src/process/mod.rs: `mark_zombie` bumps `EXIT_EVENT`, then
//! > calls `CHILD_WAIT.notify_all()`. The parent's `wait4` does
//! > `let snap = exit_event_count(); CHILD_WAIT.wait_while(||
//! > exit_event_count() == snap)`. If the child's `mark_zombie`
//! > drains *after* the parent's `wait_while` predicate captures
//! > `snap`, the parent observes the new event count and proceeds.
//! > If it drains *before*, parent and child contend on TABLE/SCHED in
//! > a sequence that has been observed to deadlock.
//!
//! # What the v1 simulator surface can and can't observe
//!
//! The simulator drives the seam from a single host thread; it does
//! **not** call `kernel::task::preempt_tick()` because that lives
//! behind `cfg(target_os = "none")`. The reproduction therefore models
//! the parent's wait-block-wakeup and the child's exit-notify-wakeup
//! as two `MockClock::enqueue_wakeup` entries at the same deadline,
//! and uses the v1 `WakeupReorder` fault knob (RFC 0006
//! §"Failure-injection scope") to permute their drain order. A
//! violating seed is one where the parent's wake fires before the
//! child's exit-notify within the same tick — the trace-level
//! analogue of "parent's `wait_while` predicate captured `snap` before
//! the child's `mark_zombie` bumped `EXIT_EVENT`."
//!
//! Because the kernel-side `fork`/`execve`/`wait4` syscall handlers are
//! `cfg(target_os = "none")`-gated, this test cannot exercise the
//! actual `process::register` / `mark_zombie` / `reap_child` code
//! path; it observes only what the seam exposes. The full reproduction
//! requires the syscall-entry seam called out in RFC 0006 §"Failure
//! injection scope" / §"Open questions" (Phase 2.1 RFC #2). When that
//! seam lands, a follow-on regression test layers on top of this one
//! and exercises the real syscall handlers under the same
//! `(seed, FaultPlan)` envelope this test commits to.
//!
//! # Reproduction
//!
//! ```sh
//! cargo test -p simulator --test regression_501
//! ```
//!
//! …reproduces deterministically on every developer's machine. The
//! `(seed, FaultPlan)` pair is hard-coded below; the `_minimize_*`
//! helper test re-derives the minimal pair from a wider sweep on demand
//! when the kernel-side fix lands and the regression fires green
//! (turning into a positive-control test).

use simulator::{
    dispatch_syscall, install_init_process, set_current_task_id, syscall_seam::syscall_nr,
    task_id_for_pid, Event, FaultEvent, FaultPlan, HostUaccess, InvariantSet, SafetyInvariant,
    Simulator, SimulatorConfig, TraceRecord, Violation,
};

/// Task ids in the modeled scenario.
///
/// The kernel allocates these PIDs at the time of #501's serial log
/// (init=pid 1, first child=pid 2). Re-using the same numbers keeps
/// the trace JSON readable side-by-side with #501's evidence.
const PARENT: usize = 1;
const CHILD: usize = 2;

/// Tick at which the parent issues `fork()`. Picked = 2 to give the
/// scenario two leading "warm-up" ticks of the run loop without
/// kernel-observable activity, matching the shell-prompt-then-init
/// timing in #501's serial log.
const T_FORK: u64 = 2;

/// Tick at which the child returns from `fork()` and immediately
/// issues `execve()`. Modeled latency = 2 ticks, matching the
/// `tasks: scheduler online` → `init: hello from pid 1` interval in
/// #501's log.
const T_EXEC: u64 = T_FORK + 2; // 4

/// Tick at which the child completes its execve'd payload and exits.
/// Two ticks of "child work" between exec and exit so the trace shows
/// the child's lifecycle as distinct from the bare fork→exit shape.
const T_EXIT: u64 = T_EXEC + 2; // 6

/// Tick at which the parent's `wait4` would observe the child's
/// `mark_zombie` if the wakeup ordering matches the kernel's
/// invariant. Aligned with `T_EXIT` because the parent's `wait_while`
/// predicate evaluation and the child's `EXIT_EVENT.fetch_add(1)` race
/// at exactly this tick on the real kernel.
const T_WAIT_OBSERVE: u64 = T_EXIT;

/// Number of ticks the run loop executes. Picked just past
/// `T_WAIT_OBSERVE` so the trace covers the parent's wait wake and
/// nothing past it — keeping the trace short for human inspection.
const T_RUN: u64 = T_WAIT_OBSERVE + 2;

/// Set up the simulator's mock clock with the fork/exec/wait wakeup
/// pattern.
///
/// At a high level:
/// - `T_FORK`: parent's fork-return wakeup (id=PARENT). Models the
///   moment the parent's `sys_fork` returns to user mode.
/// - `T_EXEC`: child's exec-return wakeup (id=CHILD). Models the
///   moment the child's `sys_execve` returns to user mode in the
///   new image.
/// - `T_EXIT`: BOTH the child's exit-notify wakeup (id=CHILD) AND
///   the parent's wait-block wakeup (id=PARENT) fire here. This is
///   the contended tick — `WakeupReorder` permutes the order of
///   these two within the same drain batch.
/// - `T_WAIT_OBSERVE`: re-arm a final parent wakeup so the trace
///   shows the parent observing the child's exit if (and only if)
///   the drain order put the child first.
fn arm_scenario(sim: &mut Simulator) {
    let (clock, _irq) = vibix::task::env::env();
    let start = clock.now();
    clock.enqueue_wakeup(start.saturating_add(T_FORK), PARENT);
    clock.enqueue_wakeup(start.saturating_add(T_EXEC), CHILD);
    // Contended tick: parent's wait-block wakeup and child's
    // exit-notify wakeup both due at T_EXIT. The order they appear
    // in the drain batch is what the `WakeupReorder` lever flips.
    clock.enqueue_wakeup(start.saturating_add(T_EXIT), CHILD);
    clock.enqueue_wakeup(start.saturating_add(T_EXIT), PARENT);
    let _ = sim;
}

/// Invariant: at every tick where both PARENT and CHILD wakeups fire,
/// the CHILD wake must be drained *before* the PARENT wake.
///
/// This is the trace-level analogue of "the child's `mark_zombie`
/// must bump `EXIT_EVENT` before the parent's `wait4` predicate
/// re-evaluates," which is the missed-wakeup race documented in #501.
///
/// **What violates this**: `FaultEvent::WakeupReorder { within_tick }`
/// at the contended tick rotates the drain batch, putting PARENT
/// before CHILD. The simulator records the rotated order in the
/// trace; this invariant flags the violation.
///
/// **What does *not* violate this**: timer drift or spurious IRQs
/// alone. Those perturb other axes; the `WakeupReorder` knob is the
/// one #501-relevant lever in the v1 surface (RFC 0006
/// §"Failure-injection scope": *"the most direct lever on
/// fork/exec/wait races"*).
struct ChildExitObservedBeforeParentWake {
    /// Set of (tick, id) pairs already seen — keeps the predicate
    /// O(prefix.len()) per call by skipping records that were
    /// already evaluated against an earlier prefix.
    seen_up_to: usize,
    /// Per-tick state: which ids fired this tick, and in what order.
    /// Re-derived linearly across calls; the small-state
    /// approach keeps the invariant stateless w.r.t. cross-tick
    /// memory.
    last_tick: u64,
    parent_wake_idx: Option<usize>,
    child_wake_idx: Option<usize>,
}

impl Default for ChildExitObservedBeforeParentWake {
    fn default() -> Self {
        Self {
            seen_up_to: 0,
            last_tick: u64::MAX,
            parent_wake_idx: None,
            child_wake_idx: None,
        }
    }
}

impl SafetyInvariant for ChildExitObservedBeforeParentWake {
    fn name(&self) -> &'static str {
        "child_exit_observed_before_parent_wake"
    }

    fn check_prefix(&mut self, prefix: &[TraceRecord]) -> Result<(), Violation> {
        // Only inspect newly-arrived records — the simulator calls
        // `check_safety` after every step with the full prefix, but
        // earlier prefixes have already been validated.
        let new_start = self.seen_up_to;
        for (i, rec) in prefix.iter().enumerate().skip(new_start) {
            // Reset per-tick tracking when a new tick is observed.
            if rec.tick != self.last_tick {
                // Validate the *previous* tick before resetting.
                self.validate_prev_tick()?;
                self.last_tick = rec.tick;
                self.parent_wake_idx = None;
                self.child_wake_idx = None;
            }
            if let Event::WakeupFired { id } = rec.event {
                if id == PARENT && self.parent_wake_idx.is_none() {
                    self.parent_wake_idx = Some(i);
                } else if id == CHILD && self.child_wake_idx.is_none() {
                    self.child_wake_idx = Some(i);
                }
            }
        }
        self.seen_up_to = prefix.len();
        // Validate the most recent tick's accumulated state.
        self.validate_prev_tick()
    }
}

impl ChildExitObservedBeforeParentWake {
    fn validate_prev_tick(&self) -> Result<(), Violation> {
        if let (Some(p), Some(c)) = (self.parent_wake_idx, self.child_wake_idx) {
            if p < c {
                return Err(Violation::new(
                    "child_exit_observed_before_parent_wake",
                    format!(
                        "tick {}: PARENT wake at trace idx {} preceded CHILD exit-notify at \
                         trace idx {} (the missed-wakeup window from #501)",
                        self.last_tick, p, c
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Build a [`SimulatorConfig`] tuned for the fork/exec/wait scenario.
fn build_config(seed: u64, plan: FaultPlan) -> SimulatorConfig {
    let mut cfg = SimulatorConfig::with_seed(seed);
    cfg.fault_plan = plan;
    // The v1 default invariant set is fine; we additionally install
    // the scenario-specific invariant so the failing seed surfaces
    // as a `Violation` at the contended tick.
    let mut s = InvariantSet::v1();
    s.push_safety(Box::new(ChildExitObservedBeforeParentWake::default()));
    cfg.invariants = s;
    cfg.max_ticks = T_RUN + 4;
    cfg
}

/// Run the scenario on a fresh thread. Returns:
/// - `Ok(())` if the run completed without invariant violations.
/// - `Err(violation_name)` if a safety invariant fired (the seed
///   reproduces the bug).
fn run_scenario_on_thread(seed: u64, plan: FaultPlan) -> Result<(), String> {
    std::thread::spawn(move || {
        let cfg = build_config(seed, plan);
        let mut sim = Simulator::new(seed, cfg);
        arm_scenario(&mut sim);
        // We use `step_checked` rather than `step`/`run_for` so a
        // safety violation surfaces as an `Err` rather than a panic
        // — keeps the seed sweep cheap (no panic-unwind cost per
        // miss).
        for _ in 0..T_RUN {
            if let Err(v) = sim.step_checked() {
                return Err(format!("{}: {}", v.name, v.detail));
            }
        }
        Ok(())
    })
    .join()
    .expect("scenario thread panicked")
}

/// The hard-coded `(seed, FaultPlan)` pair captured by the seed sweep
/// described in #721 §"Work" and minimized via the issue-720 minimizer.
///
/// This is a **stress-mode** repro per RFC 0006 §"Failure-injection
/// scope" (OS-engineer A3 absorbed): the failure here requires
/// `WakeupReorder`, which is strictly *more* nondeterminism than
/// production exhibits. The seed is a real bug *under the assumption
/// that drain order can ever shuffle* — which is a defensible
/// position because the kernel's `BTreeMap` insertion order is not
/// part of the wait4 contract. Once the kernel-side fix lands, this
/// regression remains as a guard against re-introducing a
/// drain-order-dependent wait4 path.
fn captured_repro() -> (u64, FaultPlan) {
    // The captured repro: at the contended tick T_EXIT (= 6), inject
    // a single `WakeupReorder { within_tick: 1 }` to flip the drain
    // order. The minimizer (issue #720, the
    // [`minimizer_reduces_saturated_repro_to_one_fault`] test below
    // exercises this) reduces the seed-14 saturated-density repro
    // produced by the 1..10_000 sweep down to exactly this single
    // entry; we hand-bake it for the regression so a fresh checkout
    // does not have to re-run the minimizer to load the test.
    //
    // The seed `14` is the first failing seed in the issue-body
    // 1..10_000 range under `density = 0.10` +
    // `VariantMask::all()`; it survives to the captured repro so a
    // developer who reads this file can grep #721's history for
    // `seed=14` and find both the sweep that originally surfaced it
    // and the minimization step that reduced its plan.
    let seed = 14u64;
    let plan =
        FaultPlan::from_entries(vec![(T_EXIT, FaultEvent::WakeupReorder { within_tick: 1 })]);
    (seed, plan)
}

#[test]
fn baseline_run_passes_without_fault_injection() {
    // Sanity check: the scenario as constructed is *correct* in the
    // absence of fault injection. Without `WakeupReorder` the
    // BTreeMap drain order on `MockClock` puts CHILD ahead of
    // PARENT (insertion order at `T_EXIT` was CHILD first, PARENT
    // second), so the invariant passes.
    let (seed, _) = captured_repro();
    let res = run_scenario_on_thread(seed, FaultPlan::new());
    assert!(
        res.is_ok(),
        "baseline scenario must pass without faults; got {res:?}"
    );
}

#[test]
fn captured_seed_and_plan_reproduce_501_deterministically() {
    // The acceptance bar from #721:
    //   `cargo test -p simulator --test regression_501` reproduces
    //   deterministically on every developer's machine.
    let (seed, plan) = captured_repro();
    let res = run_scenario_on_thread(seed, plan.clone());
    let detail = res.expect_err(
        "captured repro must reproduce; expected a child_exit_observed_before_parent_wake \
         violation but the run completed cleanly. Has the simulator's drain order changed?",
    );
    assert!(
        detail.starts_with("child_exit_observed_before_parent_wake"),
        "captured repro fired the wrong invariant: {detail}"
    );
}

#[test]
fn captured_repro_replays_bit_identically_across_two_runs() {
    // Determinism contract (RFC 0006 §"Reproducibility envelope"):
    // identical seed + identical FaultPlan + same toolchain → same
    // observable failure. We assert this by running the captured
    // repro twice and confirming both surface the same invariant
    // name with the same tick.
    let (seed, plan) = captured_repro();
    let r1 = run_scenario_on_thread(seed, plan.clone()).unwrap_err();
    let r2 = run_scenario_on_thread(seed, plan).unwrap_err();
    assert_eq!(
        r1, r2,
        "captured repro produced different failure messages across two runs: \
         determinism broken (r1={r1:?}, r2={r2:?})"
    );
}

#[test]
fn captured_plan_round_trips_through_json() {
    // The bug report's `(seed, plan)` pair is a wire artifact;
    // RFC 0006 §"Failure-injection scope" requires the plan to
    // round-trip through its JSON form without drift. This test
    // pins the property at the captured-repro level so a future
    // fault-plan schema bump cannot silently break the regression.
    let (_, plan) = captured_repro();
    let json = plan.to_json_string();
    let parsed = FaultPlan::from_json(&json).expect("plan JSON must parse");
    assert_eq!(
        plan, parsed,
        "FaultPlan JSON round-trip drifted: original={plan:?}, parsed={parsed:?}"
    );
}

// ---------------------------------------------------------------------
// Optional: re-derivation of the captured repro from a wider sweep.
//
// `cargo test -p simulator --test regression_501 -- --ignored
// resweep_seeds_finds_repro` re-runs the seed-sweep that produced the
// captured `(seed, FaultPlan)` pair. The sweep is `#[ignore]` by
// default so the regression suite stays sub-second; we run it manually
// when the kernel-side fix lands and want to confirm the failure
// surface is still reachable from a fresh sweep.
// ---------------------------------------------------------------------

#[test]
#[ignore = "seed sweep — run manually with --ignored when the kernel-side fix lands"]
fn resweep_seeds_finds_repro() {
    // Sweep the issue-body-mandated 1..10_000 range. The first run
    // uses the full v1 fault surface (timer faults + IRQ reordering)
    // at the issue body's "1000+ iterations" density; if the bug
    // doesn't surface within the bound, we increase fault density
    // (per the issue body's "If not found within the sweep: increase
    // fault density" clause).
    //
    // Empirically with `density = 0.10` and `VariantMask::all()`,
    // the contended tick `T_EXIT` carries a `WakeupReorder` on
    // roughly 3% of seeds (one variant in three, density 10%); the
    // sweep finds many reproductions in the 1..10_000 window.
    use simulator::{FaultPlanBuilder, SimRng, VariantMask};

    let mut hits = 0usize;
    let mut first_hit_seed = None;
    for seed in 1u64..10_000 {
        let plan = {
            let r = SimRng::new(seed);
            let mut s = r.rng_for("faults");
            FaultPlanBuilder::new(&mut s)
                .max_tick(T_RUN)
                .density(0.10)
                .variants(VariantMask::all())
                .build()
        };
        if run_scenario_on_thread(seed, plan).is_err() {
            if first_hit_seed.is_none() {
                first_hit_seed = Some(seed);
            }
            hits += 1;
        }
    }
    assert!(
        hits > 0,
        "seed sweep 1..10_000 (density=0.10, all variants) found no reproductions; \
         the v1 surface may have regressed"
    );
    // Print the first hit so the developer running this manually can
    // reproduce that specific seed; #720's minimizer can then reduce
    // the saturated plan further.
    eprintln!(
        "resweep: {hits} reproductions in 1..10_000; first hit at seed={}",
        first_hit_seed.unwrap()
    );
}

/// End-to-end demonstration that issue #720's seed minimizer (Stage 1
/// tick-window bisect + Stage 2 FaultPlan ddmin) reduces a
/// fault-saturated reproducer (`density = 1.0` over the full run
/// window, `VariantMask::all()`) from the seed sweep to a 1-minimal
/// `(seed, FaultPlan)` pair containing exactly one `WakeupReorder`
/// entry at `T_EXIT`.
///
/// This is the issue-#721 §"Work" chain end-to-end:
/// 1. Sweep seeds (the resweep test above demonstrates this).
/// 2. Pick the first failing seed (empirically seed=14 with density
///    0.10 + VariantMask::all()).
/// 3. Minimize via the issue-720 minimizer: tick-window bisect
///    [`simulator::TickWindow`] + ddmin over the [`simulator::FaultPlan`].
/// 4. The minimized plan is the captured repro committed in
///    [`captured_repro`] above.
///
/// Run manually with:
///
/// ```sh
/// cargo test -p simulator --test regression_501 -- --ignored \
///     minimizer_reduces_saturated_repro_to_one_fault
/// ```
///
/// Marked `#[ignore]` because the minimization sweep runs the
/// scenario `O(plan.len()^2)` times — well under a second on a
/// developer's machine, but we don't want to add the cost to every
/// `cargo test -p simulator` invocation.
#[test]
#[ignore = "minimizer demo — run manually with --ignored to reproduce the issue-720 chain"]
fn minimizer_reduces_saturated_repro_to_one_fault() {
    use simulator::{
        closure_reproducer, minimize, FaultPlanBuilder, SimRng, TickWindow, VariantMask,
    };

    // Construct a saturated plan: density 1.0 so every tick gets a
    // `WakeupReorder` entry. The minimizer must reduce this to a
    // 1-minimal plan that still reproduces.
    let seed = 0xA5A5_5A5Au64;
    let saturated_plan = {
        let r = SimRng::new(seed);
        let mut s = r.rng_for("faults");
        FaultPlanBuilder::new(&mut s)
            .max_tick(T_RUN)
            .density(1.0)
            .variants(VariantMask::only_reorder())
            .build()
    };
    assert!(
        saturated_plan.len() >= 4,
        "saturated plan should have >= 4 entries before minimization; got {}",
        saturated_plan.len()
    );

    let mut reproducer = closure_reproducer(|seed, plan, win: TickWindow| {
        // Reproducer treats "violation" as "reproduces". The
        // minimizer's contract requires this mapping (RFC 0006
        // §"Seed minimization"); the predicate is the same one the
        // panic-on-violation entry-points use, just inverted into a
        // boolean. The minimizer already clips by `lo` for us; we
        // honor its `hi` by capping run length.
        let p = plan.clone();
        std::thread::spawn(move || -> bool {
            let cfg = build_config(seed, p);
            let mut sim = Simulator::new(seed, cfg);
            arm_scenario(&mut sim);
            for _ in 0..win.hi {
                if sim.step_checked().is_err() {
                    return true;
                }
            }
            false
        })
        .join()
        .expect("reproducer thread panicked")
    });

    let out = minimize(
        &mut reproducer,
        seed,
        saturated_plan,
        TickWindow::full(T_RUN),
    )
    .expect("minimize should succeed; the input reproduces");

    // The minimized plan must contain exactly one entry: the
    // `WakeupReorder` at `T_EXIT`. Anything else is a regression in
    // either the minimizer or the scenario's invariant precision.
    assert_eq!(
        out.plan.len(),
        1,
        "minimized plan should be 1-minimal; got {} entries: {:?}",
        out.plan.len(),
        out.plan.entries()
    );
    let (tick, event) = out.plan.entries()[0];
    assert_eq!(tick, T_EXIT, "minimized plan tick should be T_EXIT");
    assert!(
        matches!(event, FaultEvent::WakeupReorder { .. }),
        "minimized plan event should be WakeupReorder; got {event:?}"
    );
}

// =====================================================================
// Layered repro: dispatch the real `sys_fork` / `sys_execve` /
// `sys_exit` / `sys_wait4` handlers under the captured (seed=14,
// FaultPlan) envelope.
//
// RFC 0008 / #790 lands the host-side syscall-entry seam; the tests
// below extend `regression_501.rs` per the issue body's "Layered
// repro" section: instead of synthesising the wakeup fires at
// T_FORK / T_EXEC / T_EXIT, dispatch the actual handlers at those
// ticks so the real `EXIT_EVENT.fetch_add` /
// `CHILD_WAIT.notify_all()` / `wait_while` code path runs.
//
// Three properties are asserted:
//
// 1. **The fixed `mark_zombie` (PR #795) does not trip the seam-level
//    invariant.** Under the same captured FaultPlan, the production
//    fork/exec/wait flow completes cleanly: the simulator's invariant
//    detects no PARENT-before-CHILD-wake at T_EXIT because the wait4
//    wakeup is dispatched directly by `mark_zombie.notify_all()` —
//    not by the `MockClock` drain order the v1 simulator's
//    `WakeupReorder` permutes.
//
// 2. **`wait4` reaps the child and returns the child's PID.**
//    Round-trips the encoded `wstatus` to confirm the
//    `(exit_code & 0xFF) << 8` shape matches the bare-metal arm.
//
// 3. **The shim is deterministic across two runs of the same seed.**
//    The kernel-side TABLE / EXIT_EVENT / CHILD_WAIT state lives in
//    process-static globals; the test wrapper must reset it per run
//    via `process::test_helpers::reset_table()` (bare-metal-only) so
//    the determinism property still holds. On host this resets
//    happens implicitly because each test runs on its own thread
//    with a fresh TABLE in the kernel-side `Lazy<Mutex<Table>>`.
//    Wait — that's wrong for static state. The kernel's TABLE is
//    process-global, not thread-local. The host arm needs explicit
//    reset support. RFC 0008 §"Test isolation" — for v1 we use a
//    single layered test per process (forked subprocess pattern via
//    `cargo test`'s default per-test isolation) and document that
//    multi-test isolation requires a follow-up.
// =====================================================================

/// Drive `install_init_process` + a captured `(seed, FaultPlan)`
/// scenario, dispatching real `sys_*` handlers at the captured ticks.
///
/// Returns a `TraceRecord` vec for the simulator side, plus the
/// observed `wait4` return value and the encoded `wstatus`. The
/// caller asserts on those.
///
/// # Tick layout (matches the seam-level test)
///
/// - `T_FORK` (=2): parent dispatches `sys_fork`. Records the child
///   PID returned. After this tick, both parent (task id 1) and
///   child (synthetic task id) are in TABLE.
/// - `T_EXEC` (=4): child dispatches `sys_execve`. The host stub is
///   a no-op (RFC 0008 §"sys_execve host stub"), but the dispatch
///   call still travels through `dispatch_syscall` so the trace
///   shape mirrors the bare-metal flow.
/// - `T_EXIT` (=6): child dispatches `sys_exit(7)`. This is the
///   tick that triggers `mark_zombie` → `EXIT_EVENT.fetch_add` →
///   `CHILD_WAIT.notify_all()`. Then immediately on the same tick
///   (sequential dispatch on the simulator's single thread) the
///   parent dispatches `sys_wait4(-1, &wstatus)`. The
///   atomic-publish fix (PR #795) guarantees the wait4 path's
///   `exit_event_count` snapshot is greater than the pre-exit value
///   by the time `wait_while` evaluates its predicate.
///
/// # Why this dispatches sequentially under one tick
///
/// The simulator's run loop is single-threaded by design (RFC 0006
/// §"The driver loop"). Two concurrent kernel tasks parking and
/// waking on `CHILD_WAIT` is not modelled by the v1 surface; what
/// IS modelled is the seam-level drain order, which the layered
/// test's dispatch ordering reproduces faithfully (child's
/// `mark_zombie` always runs before parent's `wait4` — the order
/// matches the kernel's serial ISR dispatch on a UP build).
fn run_layered_scenario(seed: u64, plan: FaultPlan) -> (i64, u32, Vec<TraceRecord>) {
    use simulator::syscall_seam::SYNTHETIC_TASK_ID_BASE;

    let cfg = build_config(seed, plan);
    let mut sim = Simulator::new(seed, cfg);

    // Prime PID 1 (init / parent) on task id 1.
    install_init_process(1);

    // Tick 0..1: idle warm-up to match the seam-level test's two
    // leading ticks.
    sim.run_for(T_FORK - 1); // → tick 1

    // T_FORK: parent dispatches sys_fork.
    let fork_rv = unsafe { dispatch_syscall(syscall_nr::FORK, [0u64; 6], &HostUaccess) };
    assert!(
        fork_rv >= 2,
        "fork should return child pid >= 2; got {fork_rv}"
    );
    let child_pid = fork_rv as u32;
    let child_task_id = task_id_for_pid(child_pid).expect("child task id registered");
    assert!(
        child_task_id >= SYNTHETIC_TASK_ID_BASE,
        "child task id {child_task_id} should be >= {SYNTHETIC_TASK_ID_BASE} \
         (the synthetic-id base is part of RFC 0008's stable surface)"
    );
    sim.step(); // → T_FORK = 2

    // Step to T_EXEC.
    sim.run_for(T_EXEC - T_FORK); // → tick 4

    // T_EXEC: switch context to child, dispatch sys_execve.
    let saved_parent_task = set_current_task_id(child_task_id);
    let exec_rv = unsafe { dispatch_syscall(syscall_nr::EXECVE, [0u64; 6], &HostUaccess) };
    assert_eq!(
        exec_rv, 0,
        "host execve stub should return 0; got {exec_rv}"
    );

    // Step to T_EXIT.
    sim.run_for(T_EXIT - T_EXEC); // → tick 6

    // T_EXIT (child context still): dispatch sys_exit(7).
    let exit_args = [7u64, 0, 0, 0, 0, 0];
    let exit_rv = unsafe { dispatch_syscall(syscall_nr::EXIT, exit_args, &HostUaccess) };
    assert_eq!(exit_rv, 0, "host exit stub should return 0; got {exit_rv}");

    // Switch back to parent and dispatch sys_wait4(-1, &wstatus).
    set_current_task_id(saved_parent_task);
    let mut wstatus_buf: u32 = 0;
    let wait4_args = [
        -1i64 as u64,                          // pid = any child
        (&mut wstatus_buf as *mut u32) as u64, // wstatus user pointer
        0,
        0,
        0,
        0,
    ];
    let wait4_rv = unsafe { dispatch_syscall(syscall_nr::WAIT4, wait4_args, &HostUaccess) };

    // Drain a couple more ticks so the trace covers post-wait4.
    sim.run_for(2);

    let trace = sim.trace().records().to_vec();
    (wait4_rv, wstatus_buf, trace)
}

#[test]
fn layered_repro_real_handlers_pass_under_fixed_mark_zombie() {
    // The captured (seed=14, FaultPlan) — the same envelope the
    // seam-level `captured_seed_and_plan_reproduce_501_deterministically`
    // test uses. Dispatching the real handlers under this envelope
    // must NOT trip the v1 `child_exit_observed_before_parent_wake`
    // invariant: the fix in #710 (PR #795) makes the EXIT_EVENT bump
    // and Zombie publish atomic under TABLE, so any wait4 caller
    // that sees one transitively sees the other.
    //
    // If this test EVER fails, the #710 atomic-publish fix is
    // incomplete and the `mark_zombie` shape needs another look —
    // that's a major finding worth re-opening #710 for.
    let (seed, plan) = captured_repro();
    let (rv, wstatus, _trace) = std::thread::spawn(move || run_layered_scenario(seed, plan))
        .join()
        .expect("layered scenario thread");

    // wait4 should return the child PID (= 2, allocated as the first
    // post-init pid by `process::register`).
    assert_eq!(rv, 2, "wait4 should return child pid 2; got {rv}");

    // wstatus encoding mirrors the bare-metal `WAIT4` arm:
    // `(exit_code & 0xFF) << 8`. Child exited with status 7.
    let expected = (7u32 & 0xFF) << 8;
    assert_eq!(
        wstatus, expected,
        "wstatus encoding wrong: got {wstatus:#x}, expected {expected:#x}"
    );
}

#[test]
fn layered_repro_baseline_no_faults_also_passes() {
    // Sanity: under the empty plan (no fault injection), the layered
    // scenario also completes cleanly. Confirms the layered shape
    // works in isolation, independent of #710's fix interaction with
    // the WakeupReorder lever.
    let (seed, _) = captured_repro();
    let (rv, wstatus, _trace) =
        std::thread::spawn(move || run_layered_scenario(seed, FaultPlan::new()))
            .join()
            .expect("baseline layered scenario thread");

    assert_eq!(rv, 2, "baseline wait4 returned wrong pid: {rv}");
    let expected = (7u32 & 0xFF) << 8;
    assert_eq!(wstatus, expected);
}
