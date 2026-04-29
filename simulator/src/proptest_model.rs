//! `proptest_state_machine::ReferenceStateMachine` implementation that
//! generates transition sequences for the host-side simulator.
//!
//! RFC 0006 §"RNG stream coupling: `proptest` master-seeds the
//! simulator" pinned the integration shape:
//!
//! > `proptest`'s `TestRng` master-seeds the simulator's master seed.
//! > The `SchedulerStateMachine: ReferenceStateMachine` impl reads
//! > `proptest`'s next u64 once, at `init_state`, and uses that value
//! > as `Simulator::with_seed(value)`.
//!
//! That single u64 is the entire interface between proptest's RNG and
//! the simulator's RNG. A failure surfaces as one shrunk transition
//! sequence + one master seed; replay re-runs both.
//!
//! ## Why this module is `dev-dependencies` only
//!
//! `proptest` and `proptest-state-machine` are listed under
//! `[dev-dependencies]` in `simulator/Cargo.toml`. They are pulled in
//! only for `cargo test` builds — the production simulator crate has
//! zero entropy reach. The module is therefore gated on `cfg(test)`
//! at the file level; nothing inside is reachable by callers of the
//! `simulator` library.
//!
//! ## Why we do not use `prop_state_machine!` directly
//!
//! `proptest-state-machine`'s `prop_state_machine!` macro and
//! [`StateMachineTest`] trait drive the system under test on the
//! current thread. The simulator's [`crate::Simulator::new`] panics if
//! its `MockClock` / `MockTimerIrq` mocks are installed twice on the
//! same thread (kernel-side `install_sim_env` contract — RFC 0005
//! §"Thread-local install"), which conflicts with proptest's
//! "many cases on one runner thread" pattern.
//!
//! So we use the [`ReferenceStateMachine::sequential_strategy`] half
//! of the API directly: it generates `(initial_state, Vec<transition>)`,
//! and we run each case on a freshly-spawned `std::thread`. Each
//! thread installs its own simulator, runs the transitions, joins,
//! and proptest's `TestRunner` shrinks the transition sequence on
//! failure — which is exactly the §"RNG stream coupling" shape the
//! RFC committed to.

#![cfg(test)]

use std::vec::Vec;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};
use proptest_state_machine::ReferenceStateMachine;

use crate::invariants::Violation;
use crate::trace::Trace;
use crate::{Simulator, SimulatorConfig};
use vibix::task::env::TaskId;

/// One reference-state-machine transition.
///
/// The set is RFC 0006-aligned: each transition models a high-level
/// action a Phase 2 v1 test wants to drive the kernel through. Each
/// variant carries the parameters proptest needs to *generate* the
/// transition; their semantics on the live simulator are documented
/// per-variant under [`SchedulerTransition::apply_to_simulator`].
///
/// Several transitions are stubs in v1:
///
/// - [`SchedulerTransition::Fork`] / [`SchedulerTransition::Exec`] /
///   [`SchedulerTransition::Wait`] / [`SchedulerTransition::Block`]
///   need #718's `sched_mock_trace!` emit points to surface their
///   evidence in the trace; until then they advance the reference
///   model only.
/// - [`SchedulerTransition::Wake`] is the one transition that *can*
///   be driven against the live simulator today via
///   `Clock::enqueue_wakeup` + a `step()` past the deadline. We wire
///   it through so the proptest harness exercises a real seam path
///   even before #718 lands.
/// - [`SchedulerTransition::Yield`] is `step()` once.
/// - [`SchedulerTransition::InjectFault`] is a no-op until #719's
///   `FaultPlan` lands. We keep it in the transition set so the day
///   #719 merges the strategy already generates fault-injection
///   sequences; the `apply_to_simulator` body grows then.
#[derive(Clone, Debug)]
pub enum SchedulerTransition {
    /// Spawn a child task with the given id.
    Fork {
        /// New task id.
        id: TaskId,
    },
    /// `exec` overlay on an existing task.
    Exec {
        /// Task id being exec'd.
        id: TaskId,
    },
    /// Parent waits on a child id.
    Wait {
        /// Child id to wait for.
        child: TaskId,
    },
    /// Task blocks on a deadline `delta` ticks in the future.
    Block {
        /// Task id that blocks.
        id: TaskId,
        /// Block reason index (matches [`crate::trace::BlockReason`]
        /// variant order). Read once #718's `sched_mock_trace!`
        /// emit point lands and the simulator drives an actual
        /// `TaskBlocked` event from this transition.
        #[allow(dead_code)]
        reason: u8,
    },
    /// Wake task `id` by enqueuing a wakeup at `now + delta` and
    /// stepping the simulator past it.
    Wake {
        /// Task id to wake.
        id: TaskId,
        /// Ticks until wake.
        delta: u64,
    },
    /// Cooperative yield: one `step()`.
    Yield,
    /// Stubbed fault injection — no-op until #719's `FaultPlan` lands.
    InjectFault {
        /// Fault kind index. Reserved for #719.
        #[allow(dead_code)]
        kind: u8,
    },
}

/// Reference-side state mirrored by the proptest model.
///
/// Tracks the minimum needed to define [`SchedulerStateMachine::preconditions`]
/// — alive task ids, blocked tasks. Per RFC 0006 §"Reference state
/// machine: invariants over the trace, not refinement", the reference
/// model is *not* an oracle the live trace is compared against; it
/// only generates transition sequences that the live simulator's
/// invariant set then judges.
#[derive(Clone, Debug)]
pub struct ReferenceState {
    /// Master seed for the simulator. Generated by
    /// [`SchedulerStateMachine::init_state`] from proptest's `TestRng`
    /// — this is the single u64 the RFC commits to as the integration
    /// surface.
    pub seed: u64,
    /// Tasks the model believes are alive.
    pub alive: std::collections::BTreeSet<TaskId>,
    /// Tasks the model believes are currently blocked.
    pub blocked: std::collections::BTreeSet<TaskId>,
    /// Monotonic counter for fork id allocation. Real PIDs come from
    /// the kernel; the model's `next_id` only gates when *new* tasks
    /// can be forked.
    pub next_id: TaskId,
}

impl ReferenceState {
    fn with_seed(seed: u64) -> Self {
        Self {
            seed,
            alive: core::iter::once(1).collect(),
            blocked: std::collections::BTreeSet::new(),
            next_id: 2,
        }
    }
}

/// `proptest_state_machine::ReferenceStateMachine` implementation
/// driving the host-side simulator.
pub struct SchedulerStateMachine;

impl ReferenceStateMachine for SchedulerStateMachine {
    type State = ReferenceState;
    type Transition = SchedulerTransition;

    fn init_state() -> BoxedStrategy<Self::State> {
        // The single u64 the RFC pinned as the proptest → simulator
        // integration surface. proptest's `TestRng` produces it; the
        // simulator threads it into `Simulator::new(seed)`.
        any::<u64>().prop_map(ReferenceState::with_seed).boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        // Pick from the alive task set for transitions that target an
        // existing task; fall back to id 1 (init) when the set is
        // empty.
        let alive: Vec<TaskId> = state.alive.iter().copied().collect();
        let some_id = if alive.is_empty() {
            Just(1usize).boxed()
        } else {
            proptest::sample::select(alive.clone()).boxed()
        };
        let next_id = state.next_id;

        // Note: `InjectFault` is included in the strategy but stubbed
        // in `apply_to_simulator` until #719 (FaultPlan) lands. We
        // keep the strategy weight low so it does not crowd out the
        // transitions that exercise real seam paths today.
        prop_oneof![
            // Fork: introduces a new id from the model's monotonic
            // counter. Cap arrivals so the strategy converges.
            2 => Just(SchedulerTransition::Fork { id: next_id }),
            2 => some_id.clone().prop_map(|id| SchedulerTransition::Exec { id }),
            2 => some_id.clone().prop_map(|child| SchedulerTransition::Wait { child }),
            3 => (some_id.clone(), 0u8..4).prop_map(|(id, reason)| SchedulerTransition::Block {
                id, reason,
            }),
            5 => (some_id, 1u64..16).prop_map(|(id, delta)| SchedulerTransition::Wake { id, delta }),
            5 => Just(SchedulerTransition::Yield),
            1 => (0u8..4).prop_map(|kind| SchedulerTransition::InjectFault { kind }),
        ]
        .boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match *transition {
            SchedulerTransition::Fork { id } => {
                state.alive.insert(id);
                state.next_id = state.next_id.max(id + 1);
            }
            SchedulerTransition::Exec { .. } => {}
            SchedulerTransition::Wait { child } => {
                // The model's `Wait` is best-modeled as "after this
                // transition, the child will eventually be reaped" —
                // we don't remove from `alive` here because the
                // simulator-side machinery (#718's exit emit point +
                // the `MonotonicPids` invariant) is the one that
                // judges reuse.
                let _ = child;
            }
            SchedulerTransition::Block { id, .. } => {
                state.blocked.insert(id);
            }
            SchedulerTransition::Wake { id, .. } => {
                state.blocked.remove(&id);
            }
            SchedulerTransition::Yield => {}
            SchedulerTransition::InjectFault { .. } => {
                // Stubbed until #719.
            }
        }
        state
    }

    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        match *transition {
            SchedulerTransition::Exec { id } | SchedulerTransition::Wait { child: id } => {
                state.alive.contains(&id)
            }
            SchedulerTransition::Block { id, .. } => {
                state.alive.contains(&id) && !state.blocked.contains(&id)
            }
            SchedulerTransition::Wake { id, .. } => state.blocked.contains(&id),
            // Fork / Yield / InjectFault are always valid.
            SchedulerTransition::Fork { .. }
            | SchedulerTransition::Yield
            | SchedulerTransition::InjectFault { .. } => true,
        }
    }
}

/// Apply one transition to the simulator on the current thread.
///
/// Returns the first invariant violation, if any.
///
/// Every transition that needs #718's emit points to surface evidence
/// in the trace is a no-op against the simulator today; only `Wake`
/// (real seam path) and `Yield` actually mutate the simulator state.
fn apply_to_simulator(
    sim: &mut Simulator,
    transition: &SchedulerTransition,
) -> Result<(), Violation> {
    match *transition {
        SchedulerTransition::Fork { .. }
        | SchedulerTransition::Exec { .. }
        | SchedulerTransition::Wait { .. }
        | SchedulerTransition::Block { .. } => {
            // No-op until #718's `sched_mock_trace!` emit points land.
            // The model's `apply` updates the reference state; the
            // live simulator has nothing to do here yet.
            sim.step_checked()
        }
        SchedulerTransition::Wake { id, delta } => {
            // The one transition that drives a real seam path today:
            // enqueue a wakeup at `now + delta`, then step `delta`
            // ticks so the deadline drains. This exercises
            // `Clock::enqueue_wakeup` / `Clock::drain_expired` and
            // the resulting `WakeupFired` event passes through the
            // full safety-invariant suite.
            let (clock, _irq) = vibix::task::env::env();
            let now = clock.now();
            let deadline = now.saturating_add(delta);
            clock.enqueue_wakeup(deadline, id);
            for _ in 0..=delta {
                sim.step_checked()?;
            }
            Ok(())
        }
        SchedulerTransition::Yield => sim.step_checked(),
        SchedulerTransition::InjectFault { .. } => {
            // Stubbed until #719's FaultPlan lands. Skipped from the
            // simulator side; the proptest strategy still generates
            // it so the day #719 merges the existing shrink
            // sequences include fault-injection points.
            Ok(())
        }
    }
}

/// Run one reference-generated transition sequence against a freshly
/// constructed simulator on a fresh thread.
///
/// We spawn a thread because the kernel-side `install_sim_env` panics
/// on second installation per OS thread; proptest reuses one runner
/// thread across many cases, so we sandbox each case to its own
/// thread.
fn run_case(
    seed: u64,
    transitions: Vec<SchedulerTransition>,
) -> Result<Trace, (u64, Vec<SchedulerTransition>, Violation)> {
    let transitions_for_thread = transitions.clone();
    let join = std::thread::spawn(move || -> Result<Trace, Violation> {
        let mut sim = Simulator::new(seed, SimulatorConfig::with_seed(seed));
        for t in &transitions_for_thread {
            apply_to_simulator(&mut sim, t)?;
        }
        sim.check_liveness()?;
        Ok(sim.trace().clone())
    });
    match join.join() {
        Ok(Ok(trace)) => Ok(trace),
        Ok(Err(v)) => Err((seed, transitions, v)),
        Err(panic) => {
            // A panic on the worker thread is itself a test failure;
            // surface it as a synthetic Violation so proptest's
            // shrinker sees a `Result`-shaped error to drive on.
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic>".to_string());
            Err((seed, transitions, Violation::new("simulator_panic", msg)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: `init_state` reads exactly one u64 from proptest's
    /// `TestRng` and that value flows to `Simulator::new(seed)`.
    ///
    /// This is the property RFC 0006 §"RNG stream coupling" pins as
    /// the integration surface.
    #[test]
    fn init_state_seeds_simulator_with_one_u64() {
        let mut runner = TestRunner::default();
        let strat = SchedulerStateMachine::init_state();
        let tree = strat.new_tree(&mut runner).expect("init_state strategy");
        let state = tree.current();
        // The seed is whatever proptest produced — we just check the
        // round-trip into the simulator and back.
        let seed = state.seed;
        let join = std::thread::spawn(move || {
            let sim = Simulator::with_seed(seed);
            assert_eq!(sim.seed().as_u64(), seed);
        });
        join.join().expect("thread");
    }

    /// `Wake` exercises the real seam path. A short generated
    /// sequence with at least one `Wake` produces `WakeupFired`
    /// records in the trace, and every safety invariant passes.
    #[test]
    fn wake_drives_seam_and_invariants_pass() {
        let trace = run_case(
            0xCAFE_F00D,
            vec![
                SchedulerTransition::Yield,
                SchedulerTransition::Fork { id: 2 },
                SchedulerTransition::Block { id: 1, reason: 0 },
                SchedulerTransition::Wake { id: 1, delta: 3 },
                SchedulerTransition::Yield,
            ],
        )
        .expect("clean run");
        let woke = trace
            .records()
            .iter()
            .filter(|r| matches!(r.event, crate::Event::WakeupFired { id: 1 }))
            .count();
        assert!(woke >= 1, "expected at least one WakeupFired for id 1");
    }

    /// Full proptest sweep: generate a 1..16-step transition sequence,
    /// run it on a fresh thread per case, demand every safety + liveness
    /// invariant passes. This is the merge gate the issue asks for —
    /// the strategy + state-machine + invariant-set roundtrip works
    /// end-to-end.
    ///
    /// The transition count is deliberately small (16) and case count
    /// modest (32) to keep wall-clock under the host CI budget while
    /// still exercising the strategy on every tick of every case.
    #[test]
    fn proptest_sweep_invariants_hold() {
        let mut runner = TestRunner::new(Config {
            cases: 32,
            failure_persistence: None,
            ..Config::default()
        });
        let strat = SchedulerStateMachine::sequential_strategy(1..16usize);
        runner
            .run(&strat, |(initial, transitions, _)| {
                let result = run_case(initial.seed, transitions);
                if let Err((seed, _trans, v)) = result {
                    return Err(proptest::test_runner::TestCaseError::fail(format!(
                        "seed={seed:#x}: {v}"
                    )));
                }
                Ok(())
            })
            .expect("proptest sweep failed");
    }

    /// Determinism gate: two runs of the same `(seed, transition
    /// sequence)` produce byte-identical traces. This is the property
    /// the RFC §"Reproducibility Envelope" treats as a P0 review
    /// block; without it, shrinking is pointless.
    #[test]
    fn replay_is_deterministic() {
        let transitions = vec![
            SchedulerTransition::Yield,
            SchedulerTransition::Fork { id: 2 },
            SchedulerTransition::Wake { id: 1, delta: 5 },
            SchedulerTransition::Yield,
            SchedulerTransition::Block { id: 2, reason: 1 },
            SchedulerTransition::Wake { id: 2, delta: 7 },
        ];
        let a = run_case(0x1234_5678, transitions.clone()).expect("a");
        let b = run_case(0x1234_5678, transitions).expect("b");
        assert_eq!(
            a.records(),
            b.records(),
            "two runs of the same seed produced different traces"
        );
    }
}
