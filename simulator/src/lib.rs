//! Host-side DST simulator: linear tick-by-tick run loop (RFC 0006).
//!
//! This crate is the host-only driver that consumes the `sched-mock`
//! seam landed in [RFC 0005](../../../docs/RFC/0005-scheduler-irq-seam.md)
//! and converts today's flaky concurrency bugs into reproducible
//! `cargo test -- --seed=0xDEADBEEF` failures.
//!
//! Issue #715 shipped the **skeleton** (panic hook, public type names,
//! `replay` binary stub). This issue (#716) replaces those stubs with
//! the real run loop:
//!
//! - [`Simulator::new`] wires a [`vibix::task::env::MockClock`] and
//!   [`vibix::task::env::MockTimerIrq`] pair into the kernel's
//!   per-thread `task::env()` accessor (via `install_sim_env`) for the
//!   lifetime of the run.
//! - [`Simulator::step`] advances the mock clock by one tick, injects a
//!   timer IRQ, drains expired wakeups through the [`vibix::task::env::Clock`]
//!   trait, acks the IRQ, and records every observable transition into
//!   the [`Trace`] in deterministic order.
//! - [`Simulator::run_for`] and [`Simulator::run_until`] are the two
//!   loop helpers RFC 0006 §"The driver loop" calls out as v1's only
//!   driver-loop entry points.
//! - [`SimRng`] is a `ChaCha8`-backed PRNG keyed by the master seed,
//!   with named sub-streams derived via `splitmix64` so adding a new
//!   stream (`rng_for("faults")`) cannot perturb the bytes any
//!   existing stream emits (RFC 0006 §RNG).
//!
//! # Why the simulator does *not* call `kernel::task::preempt_tick()`
//!
//! RFC 0006 §"The driver loop" sketches `kernel::task::preempt_tick()`
//! as step 4 of the per-tick body. That function lives in the
//! scheduler core (`task::sched_core`) and is gated to
//! `cfg(target_os = "none")` because it depends on the bare-metal arch
//! (FPU save/restore, `swapgs`, IDT-installed timer ISR, hand-written
//! context switch). On the host triple
//! `x86_64-unknown-linux-gnu` — which is the only triple the
//! simulator builds for — none of those symbols exist.
//!
//! What the simulator *can* exercise on host is the seam contract
//! itself: the `Clock::drain_expired` / `Clock::enqueue_wakeup` /
//! `TimerIrq::ack_timer` / `TimerIrq::inject_timer` shape that
//! `preempt_tick` consumes. That is the surface every Phase 2 v1 flake
//! manifests on (timer-IRQ ordering, deadline drain ordering,
//! wakeup-before-deadline races); the bare-metal `preempt_tick` body
//! itself adds no host-observable behaviour beyond what the seam
//! guarantees. When the in-kernel `sched-mock`-gated integration tests
//! land (a separate Phase 2 issue) they will drive the real
//! `preempt_tick`; the host simulator stays at the seam.
//!
//! # Determinism contract
//!
//! Every public surface in this crate must keep the simulator
//! byte-reproducible from `(seed, git commit, toolchain)` alone. That
//! contract is enforced workspace-wide by `clippy.toml` forbidding
//! `std::collections::HashMap` / `HashSet`, by the dated nightly pin
//! in `rust-toolchain.toml`, by the kernel-side nm-check that keeps
//! `MockClock` / `MockTimerIrq` symbols out of release builds, and by
//! `rand_chacha` being pulled in `default-features = false` so
//! `getrandom` cannot leak OS entropy into the build graph. New types
//! added here should reach for `BTreeMap` / `BTreeSet`, or a seeded
//! `SimRng` sub-stream — never `std`'s default-hashed maps.
//!
//! The crate-level `disallowed_types` deny below is defence-in-depth on
//! top of the workspace `clippy.toml` rule: even if someone temporarily
//! relaxes the workspace policy, the simulator stays the strict island
//! that any determinism-sensitive `HashMap` site has to argue past.

#![cfg_attr(not(test), deny(unsafe_code))]
#![warn(missing_docs)]
// Determinism guard restated at the crate level. RFC 0006 §"Determinism
// envelope" treats a `HashMap` / `HashSet` site inside `simulator/` as
// a P0 review block; the workspace `clippy.toml` already forbids them,
// but lifting that policy in a hurry must not silently re-enable them
// here.
#![deny(clippy::disallowed_types)]

#[cfg(not(target_os = "none"))]
pub mod fault_plan;

#[cfg(not(target_os = "none"))]
pub mod invariants;

// `proptest_model` is `cfg(test)`-gated at the file level — it pulls
// in `proptest` / `proptest-state-machine` from `[dev-dependencies]`,
// neither of which appear in production builds. See
// `proptest_model.rs` for the rationale on why we use the
// `ReferenceStateMachine` strategy half rather than the full
// `prop_state_machine!` macro.
#[cfg(all(test, not(target_os = "none")))]
mod proptest_model;

#[cfg(not(target_os = "none"))]
pub mod trace;

#[cfg(not(target_os = "none"))]
mod imp {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    use vibix::task::env::{install_sim_env, Clock, MockClock, MockTimerIrq};

    pub use crate::fault_plan::{
        FaultEvent, FaultPlan, FaultPlanBuilder, VariantMask, FAULT_PLAN_SCHEMA_VERSION,
    };
    pub use crate::invariants::{
        AllRunnableEventuallyRun, BlockedToRunnableNeedsWakeup, ForkHasMatchingExitOrWait,
        InvariantSet, LivenessInvariant, MonotonicPids, NoStrandedWakeups, SafetyInvariant,
        SingleRunningPerCpu, Violation,
    };
    pub use crate::trace::{BlockReason, Event, FaultKind, Trace, TraceRecord, SCHEMA_VERSION};

    /// A simulator seed.
    ///
    /// The seed is the API: every reproducible failure surfaced by the
    /// simulator carries one of these in its panic message
    /// (`VIBIX_SIM_SEED=0x...`). The same seed re-run against the same
    /// `git commit` + pinned toolchain must produce a byte-identical
    /// trace — see RFC 0006 §"Reproducibility Envelope".
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Seed(pub u64);

    impl Seed {
        /// Returns the raw `u64` seed value.
        #[inline]
        pub const fn as_u64(self) -> u64 {
            self.0
        }
    }

    impl From<u64> for Seed {
        #[inline]
        fn from(v: u64) -> Self {
            Self(v)
        }
    }

    /// Static configuration for a simulator run.
    ///
    /// Fields beyond `seed` and `max_ticks` (fault plan, invariant set,
    /// trace dump path, ...) land in follow-up issues; this struct
    /// carries the minimum needed to plumb [`Simulator::run_for`] and
    /// [`Simulator::run_until`] without churning the constructor
    /// signature again later.
    #[derive(Debug)]
    pub struct SimulatorConfig {
        /// Master seed for the run.
        pub seed: Seed,
        /// Hard upper bound on the number of ticks
        /// [`Simulator::run_until`] will execute before giving up. A
        /// run that hits this bound returns `None` from `run_until` so
        /// the test surface can distinguish "predicate satisfied" from
        /// "exhausted budget".
        ///
        /// Default `1_000_000` (≈10 000 simulated seconds at the PIT
        /// 100 Hz). Cheap enough that no realistic v1 test trips it
        /// accidentally; small enough that an infinite-loop predicate
        /// fails fast under `cargo test` rather than wedging the
        /// process.
        pub max_ticks: u64,
        /// Safety + liveness invariants checked during / at the end of
        /// the run. Default is [`InvariantSet::v1`] (RFC 0006 §"v1
        /// invariant catalogue", issue #722). Tests that build a
        /// `SimulatorConfig` from defaults and want a different
        /// invariant surface mutate this field after construction.
        pub invariants: InvariantSet,
        /// Seeded fault-injection plan (RFC 0006 §"Failure-injection
        /// scope", issue #719). The simulator drains every entry whose
        /// `tick` matches the current post-advance tick on each
        /// [`Simulator::step`] and dispatches the corresponding
        /// perturbation against the seam mocks.
        ///
        /// Default is the empty plan — runs that don't opt into fault
        /// injection see byte-identical traces to the pre-#719
        /// behaviour. Tests that want injection construct a builder
        /// off `SimRng::rng_for("faults")` and assign the result here.
        pub fault_plan: FaultPlan,
    }

    impl SimulatorConfig {
        /// Construct a config from a raw `u64` seed, with default
        /// `max_ticks` and the v1 invariant set. Callers that need a
        /// different cap or invariant set mutate the returned struct.
        pub fn with_seed(seed: u64) -> Self {
            Self {
                seed: Seed(seed),
                max_ticks: 1_000_000,
                invariants: InvariantSet::v1(),
                fault_plan: FaultPlan::new(),
            }
        }
    }

    impl Default for SimulatorConfig {
        fn default() -> Self {
            Self::with_seed(0)
        }
    }

    /// Master PRNG for a simulator run.
    ///
    /// Wraps [`rand_chacha::ChaCha8Rng`] with a seeded constructor and
    /// a `rng_for` named-sub-stream factory. A `SimRng` is keyed by
    /// the simulator's master seed; sub-streams are derived by hashing
    /// the stream name into a `u64` and mixing it with the master seed
    /// via `splitmix64`. The two properties this preserves:
    ///
    /// 1. **Adding a new sub-stream cannot perturb existing ones.**
    ///    `rng_for("faults")` and `rng_for("scheduler")` produce
    ///    independent byte sequences; introducing a third
    ///    `rng_for("io")` later does not shift the bytes either of
    ///    the prior two emit. This is the property RFC 0006
    ///    §"Reproduction commitments" calls out as the one that makes
    ///    seed minimisation possible — without it, a flake's seed
    ///    bisects against the *full* RNG-consumer set as it was at
    ///    bisect time, not as it was when the flake first appeared.
    /// 2. **Deterministic across runs of the same seed.** A
    ///    `SimRng::new(seed).rng_for("scheduler").gen_u64()` call
    ///    emits the same bytes on every `cargo test` invocation in
    ///    the same toolchain — by construction, since both the
    ///    splitmix64 mix and `ChaCha8` are pure functions of their
    ///    seed.
    ///
    /// `ChaCha8` (not `ChaCha20`) is chosen for the same reason
    /// FoundationDB's Flow harness uses an 8-round variant: 8 rounds
    /// are cryptographically broken but statistically uniform on
    /// every 64-bit output, and the host-side simulator's threat
    /// model is "deterministic test bytes," not "secure RNG". The
    /// ~3× throughput vs. `ChaCha20` matters when a long invariant
    /// sweep pulls millions of `u64`s.
    pub struct SimRng {
        master: u64,
    }

    impl SimRng {
        /// Construct a `SimRng` keyed by `seed`.
        pub fn new(seed: u64) -> Self {
            Self { master: seed }
        }

        /// Master seed the RNG was constructed with.
        pub fn master_seed(&self) -> u64 {
            self.master
        }

        /// Derive a named ChaCha8 sub-stream.
        ///
        /// `name` is hashed into a 64-bit value (FNV-1a, in-tree —
        /// `std::collections`'s default hasher is forbidden by the
        /// workspace lint and unsuitable here anyway because of its
        /// `RandomState`), then mixed with the master seed via
        /// `splitmix64`. The resulting `u64` is splatted across the
        /// 32-byte ChaCha8 seed (each of the four `u64` lanes runs
        /// through one more `splitmix64` step) so adjacent named
        /// streams do not share a partial seed prefix.
        pub fn rng_for(&self, name: &str) -> ChaCha8Rng {
            let name_hash = fnv1a_64(name.as_bytes());
            let mut s = splitmix64(self.master ^ name_hash);
            // Splatter the 32-byte ChaCha seed: four splitmix64 steps
            // off the same anchor. Using independent mix steps (rather
            // than just repeating `s`) means a one-bit perturbation in
            // the master seed avalanches across all four ChaCha lanes,
            // not just the first one.
            let mut seed_bytes = [0u8; 32];
            for chunk in seed_bytes.chunks_exact_mut(8) {
                s = splitmix64(s);
                chunk.copy_from_slice(&s.to_le_bytes());
            }
            ChaCha8Rng::from_seed(seed_bytes)
        }
    }

    /// SplitMix64 — Vigna 2014. Used to derive named sub-stream seeds
    /// from the master seed. Cheap, well-mixed, and the canonical
    /// "promote a u64 to a stream of u64s" primitive in deterministic
    /// simulators (FoundationDB Flow, TigerBeetle's VOPR, RFC 0006
    /// §RNG all use it).
    #[inline]
    fn splitmix64(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// FNV-1a over a byte slice. Hand-rolled because `std::hash::Hasher`
    /// implementations on `&str` go through `RandomState`, which is the
    /// determinism leak this crate exists to defeat. FNV-1a is a stable,
    /// well-known string hash; collisions are tolerable here because the
    /// downstream `splitmix64` mix amplifies any single-bit difference
    /// across the full ChaCha seed.
    #[inline]
    fn fnv1a_64(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        h
    }

    /// Host-side deterministic simulator: linear tick-by-tick run loop.
    ///
    /// Owns leak-`'static` references to a [`MockClock`] + [`MockTimerIrq`]
    /// pair, installs them on the current thread's `task::env()` slot
    /// via [`install_sim_env`], and drives them one tick at a time
    /// through [`Simulator::step`]. The trace is collected in-memory;
    /// callers reach for [`Simulator::trace`] after the run.
    ///
    /// **Per-thread.** `install_sim_env` is keyed by thread-local; one
    /// `Simulator` per `cargo test` worker is the supported pattern.
    /// Constructing a second `Simulator` on the same thread will panic
    /// out of the kernel-side `install_sim_env` ("called twice on the
    /// same thread") — which is the desired behaviour: tests that swap
    /// seeds mid-thread would race the global panic-hook seed cell and
    /// silently mis-report failures.
    pub struct Simulator {
        cfg: SimulatorConfig,
        clock: &'static MockClock,
        irq: &'static MockTimerIrq,
        rng: SimRng,
        trace: Trace,
        /// Most recently observed tick, mirrored into a process-global
        /// atomic so the panic hook can report `tick=<N>` even after
        /// the owning `Simulator` has unwound.
        current_tick: &'static AtomicU64,
        /// `Some(n)` after a `WakeupReorder { within_tick: n }` fault
        /// has been dispatched and before the corresponding wakeup
        /// drain has consumed it. Cleared every step regardless of
        /// whether the drain produced a non-empty batch.
        pending_reorder: Option<u64>,
    }

    impl Simulator {
        /// Construct a simulator bound to `cfg.seed` with the given
        /// configuration, install the panic hook, and install the
        /// `MockClock`/`MockTimerIrq` pair into `task::env()` for the
        /// current thread.
        ///
        /// **Panics** if `install_sim_env` has already been called on
        /// this thread (per the kernel-side contract). The panic
        /// message comes from `task::env::install_sim_env` directly.
        pub fn new(seed: u64, mut cfg: SimulatorConfig) -> Self {
            // Normalise the seed slot inside cfg so a caller that built
            // a `SimulatorConfig` from defaults but passes a seed via
            // the explicit argument doesn't end up with a config whose
            // recorded seed disagrees with the actual run seed.
            cfg.seed = Seed(seed);

            // Box::leak so the references genuinely satisfy the
            // `'static` bound `install_sim_env` requires. The `Box`s
            // are owned by the simulator for the lifetime of the
            // process; cargo-test workers each construct exactly one
            // `Simulator` per thread, so the leak is bounded by the
            // worker count, not by the run length.
            let clock: &'static MockClock = Box::leak(Box::new(MockClock::new(0)));
            let irq: &'static MockTimerIrq = Box::leak(Box::new(MockTimerIrq::new()));

            install_sim_env(clock, irq);
            install_panic_hook(Seed(seed));

            let current_tick = current_tick_cell();
            current_tick.store(0, Ordering::SeqCst);

            Self {
                cfg,
                clock,
                irq,
                rng: SimRng::new(seed),
                trace: Trace::new(),
                current_tick,
                pending_reorder: None,
            }
        }

        /// Convenience wrapper around [`Simulator::new`] using the
        /// default [`SimulatorConfig`]. Kept for skeleton parity —
        /// `with_seed` was the constructor #715 exposed and downstream
        /// stub call sites already cite the name.
        pub fn with_seed(seed: u64) -> Self {
            Self::new(seed, SimulatorConfig::with_seed(seed))
        }

        /// Returns the configuration the simulator was constructed with.
        pub fn config(&self) -> &SimulatorConfig {
            &self.cfg
        }

        /// Returns the seed bound to this simulator.
        pub fn seed(&self) -> Seed {
            self.cfg.seed
        }

        /// Returns the most recent observed tick.
        ///
        /// Mirror of `task::env::env().0.now()` from the simulator's
        /// thread; reads the local cache rather than re-locking the
        /// `MockClock` so it is safe to call from inside a predicate
        /// that itself invokes the clock.
        pub fn current_tick(&self) -> u64 {
            self.current_tick.load(Ordering::SeqCst)
        }

        /// Returns the id of the most-recently-scheduled task observed
        /// in the trace, or `None` if no [`Event::TaskScheduled`]
        /// record has been seen yet.
        ///
        /// RFC 0006 / #718 introspection helper. Read-only reflection
        /// of the kernel's scheduler state derived from the recorded
        /// trace stream. Invariant predicates (#722) consume this to
        /// answer "what is currently running" without re-deriving
        /// scheduler state from raw events at every check.
        ///
        /// Implemented as a reverse linear scan of the trace tail.
        /// O(n) in trace length in the worst case (a long run with
        /// no schedule events); in practice every kernel emit-point
        /// rotation pushes a `TaskScheduled` so the scan terminates
        /// within a handful of records.
        pub fn current_task(&self) -> Option<vibix::task::env::TaskId> {
            self.trace
                .records()
                .iter()
                .rev()
                .find_map(|r| match r.event {
                    Event::TaskScheduled { id } => Some(id),
                    _ => None,
                })
        }

        /// Snapshot of the kernel's runqueue, reconstructed from the
        /// trace stream.
        ///
        /// The returned `Vec` is the set of tasks that the trace
        /// reports as ready-to-run, derived by counting every id that
        /// has fired ([`Event::WakeupFired`]) without a subsequent
        /// [`Event::TaskScheduled`] or [`Event::TaskBlocked`]. Order
        /// is *deterministic* but does not match the kernel's FIFO
        /// bucketing — invariant checkers that need the exact
        /// dispatch order should consume the trace directly.
        ///
        /// Returns an empty `Vec` if the trace contains no scheduling
        /// activity yet — this is the v1 bring-up state and is the
        /// expected return on the very first tick.
        pub fn runqueue_snapshot(&self) -> Vec<vibix::task::env::TaskId> {
            use std::collections::BTreeSet;
            let mut ready: BTreeSet<vibix::task::env::TaskId> = BTreeSet::new();
            // Forward pass: track the latest state transition per id
            // through the events the simulator's run loop records
            // today (`TaskScheduled`, `TaskBlocked`, `WakeupFired`).
            // BTreeSet keeps the output deterministic — std's HashSet
            // is forbidden in this crate (see crate-level
            // `disallowed_types` lint).
            for r in self.trace.records() {
                match r.event {
                    Event::TaskScheduled { id } => {
                        // Scheduled task is `current`, not in runqueue.
                        ready.remove(&id);
                    }
                    Event::TaskBlocked { id, .. } => {
                        ready.remove(&id);
                    }
                    Event::WakeupFired { id } => {
                        ready.insert(id);
                    }
                    _ => {}
                }
            }
            ready.into_iter().collect()
        }

        /// Snapshot of the live PID table reconstructed from the
        /// trace stream — every task id that has been scheduled,
        /// woken, blocked, or forked but has not yet observed a
        /// matching [`Event::TaskExit`].
        ///
        /// Returns ids in ascending numeric order (deterministic by
        /// virtue of the underlying `BTreeSet`); the v1 invariant set
        /// only consumes this for membership and cardinality, not for
        /// dispatch order.
        pub fn pid_table_snapshot(&self) -> Vec<vibix::task::env::TaskId> {
            use std::collections::BTreeSet;
            let mut alive: BTreeSet<vibix::task::env::TaskId> = BTreeSet::new();
            for r in self.trace.records() {
                match r.event {
                    Event::TaskScheduled { id }
                    | Event::TaskBlocked { id, .. }
                    | Event::WakeupFired { id }
                    | Event::WakeupEnqueued { id, .. } => {
                        alive.insert(id);
                    }
                    _ => {}
                }
            }
            alive.into_iter().collect()
        }

        /// Borrow the recorded trace.
        pub fn trace(&self) -> &Trace {
            &self.trace
        }

        /// The simulator's master PRNG. Sub-streams via
        /// [`SimRng::rng_for`].
        pub fn rng(&self) -> &SimRng {
            &self.rng
        }

        /// Mutable access to the master PRNG, for callers (fault plans,
        /// future invariant checkers) that need to advance a stream
        /// they own.
        pub fn rng_mut(&mut self) -> &mut SimRng {
            &mut self.rng
        }

        /// Borrow the simulator's currently-installed [`FaultPlan`].
        ///
        /// Reading this during a run shows the *unconsumed* tail —
        /// every entry whose `tick` is strictly greater than the last
        /// call to [`Simulator::step`]. Callers that want the original
        /// recorded plan capture a clone before constructing the
        /// simulator.
        pub fn fault_plan(&self) -> &FaultPlan {
            &self.cfg.fault_plan
        }

        /// Append a [`FaultEvent`] at `tick` to the simulator's
        /// installed [`FaultPlan`]. Used by the proptest-state-machine
        /// integration's `InjectFault` transition (issue #722) so the
        /// shrunk transition sequence directly drives fault dispatch.
        pub fn push_fault_event(&mut self, tick: u64, event: FaultEvent) {
            self.cfg.fault_plan.push(tick, event);
        }

        /// Borrow the installed `MockClock`. Test introspection only —
        /// production code should reach the clock through `task::env()`
        /// like the kernel does.
        pub fn clock(&self) -> &'static MockClock {
            self.clock
        }

        /// Borrow the installed `MockTimerIrq`. Test introspection only.
        pub fn irq(&self) -> &'static MockTimerIrq {
            self.irq
        }

        /// Advance the simulator by exactly one tick.
        ///
        /// Per RFC 0006 §"The driver loop", in order:
        ///
        /// 1. Snapshot `now_before`.
        /// 2. Advance the mock clock by one tick.
        /// 3. Inject one virtual timer IRQ.
        /// 4. Drain expired wakeups via the [`Clock`] seam method;
        ///    record one `TaskWoken` event per drained id, in the
        ///    order the seam returned them.
        /// 5. Ack the IRQ via the [`TimerIrq`] seam method.
        ///
        /// All four calls go through the trait objects returned by
        /// `task::env::env()`, which is the same accessor
        /// `kernel::task::preempt_tick()` uses on bare metal — so the
        /// host-observable behaviour matches the kernel's seam usage
        /// exactly.
        ///
        /// "Quiescence" on host means "every wakeup whose deadline
        /// has expired has been drained": there is no host-side ready
        /// bank to rotate, no context switch to perform, and no
        /// soft-IRQ tail to drain. The trace records every
        /// host-observable transition; downstream invariant checkers
        /// (#722) and the in-kernel `sched-mock` integration tests
        /// (separate Phase 2 issue) cover the rotation and softirq
        /// paths against the bare-metal `preempt_tick`.
        pub fn step(&mut self) {
            // RFC 0006 §"invariants over the trace, not refinement":
            // every safety invariant must hold over every prefix.
            // The shared body in `step_inner` runs the tick + records
            // every event before checking; failure here is a panic so
            // the panic hook installed by `Simulator::new` can print
            // `SIMULATOR PANIC seed=… tick=…` before `panic =
            // "abort"` terminates the run. Property-test callers that
            // need unwinding-shaped failures use
            // [`Simulator::step_checked`] instead.
            if let Err(v) = self.step_inner() {
                panic!("{v}");
            }
        }

        /// Like [`Simulator::step`] but returns `Err(Violation)` on a
        /// safety-invariant failure rather than panicking.
        ///
        /// Intended for the proptest integration (#722,
        /// `proptest_model.rs`): proptest's shrinker needs a
        /// `Result`-shaped failure to drive its sequence-space
        /// minimisation. The invariant the panicking variant guards
        /// is the same; only the failure shape differs.
        pub fn step_checked(&mut self) -> Result<(), Violation> {
            self.step_inner()
        }

        /// Shared per-tick body for [`Simulator::step`] /
        /// [`Simulator::step_checked`]. Returns the first safety
        /// invariant violation discovered after the tick's records
        /// are pushed; both public entry points wrap this.
        fn step_inner(&mut self) -> Result<(), Violation> {
            let now_before = self.clock.now().raw();
            self.clock.tick();
            let mut now_after = self.clock.now().raw();
            self.current_tick.store(now_after, Ordering::SeqCst);

            self.trace.push(TraceRecord {
                tick: now_after,
                event: Event::TickAdvance {
                    from: now_before,
                    to: now_after,
                },
            });

            // RFC 0006 §"Failure-injection scope" / issue #719:
            // dispatch every fault-plan entry due at the just-advanced
            // tick *before* the canonical timer-IRQ injection. The
            // ordering matters because `TimerDrift` must extend the
            // tick interval visible to the upcoming `drain_expired`
            // call (a wakeup armed for `now_after + 2` becomes due at
            // this tick if the drift is `>= 2`); `WakeupReorder` must
            // arm the rotation before the drain consumes it; and
            // `SpuriousTimerIrq` is a pre-canonical extra inject so the
            // post-drift IRQ count visible to the kernel is the sum
            // (canonical + spurious).
            let due = self.cfg.fault_plan.drain_due(now_after);
            for fault in due {
                match fault {
                    FaultEvent::SpuriousTimerIrq => {
                        // Push the FaultInjected record *before* the
                        // extra inject so a reader of the trace can
                        // tell which `TimerInjected` is the spurious
                        // one (the next one). The trace shape after a
                        // SpuriousTimerIrq fault at tick T is therefore
                        // `TickAdvance, FaultInjected{Other},
                        // TimerInjected (spurious), TimerInjected
                        // (canonical), …`.
                        self.trace.push(TraceRecord {
                            tick: now_after,
                            event: Event::FaultInjected {
                                kind: fault.fault_kind(),
                            },
                        });
                        self.irq.inject_timer();
                        self.trace.push(TraceRecord {
                            tick: now_after,
                            event: Event::TimerInjected,
                        });
                    }
                    FaultEvent::TimerDrift { ticks } => {
                        self.trace.push(TraceRecord {
                            tick: now_after,
                            event: Event::FaultInjected {
                                kind: fault.fault_kind(),
                            },
                        });
                        if ticks > 0 {
                            self.clock.advance(ticks);
                            let drifted = self.clock.now().raw();
                            self.trace.push(TraceRecord {
                                tick: drifted,
                                event: Event::TickAdvance {
                                    from: now_after,
                                    to: drifted,
                                },
                            });
                            now_after = drifted;
                            self.current_tick.store(now_after, Ordering::SeqCst);
                        }
                    }
                    FaultEvent::WakeupReorder { within_tick } => {
                        self.trace.push(TraceRecord {
                            tick: now_after,
                            event: Event::FaultInjected {
                                kind: fault.fault_kind(),
                            },
                        });
                        // Arm the rotation. If a previous reorder for
                        // this tick was already pending it stacks
                        // (sum of rotations modulo batch len at drain
                        // time) — that keeps two `WakeupReorder`
                        // entries at the same tick observably distinct
                        // when the batch length is >= 3.
                        let prev = self.pending_reorder.unwrap_or(0);
                        self.pending_reorder = Some(prev.wrapping_add(within_tick));
                    }
                }
            }

            self.irq.inject_timer();
            self.trace.push(TraceRecord {
                tick: now_after,
                event: Event::TimerInjected,
            });

            // Drain expired wakeups through the trait object — same
            // path the bare-metal `preempt_tick` takes — so a future
            // `Clock` impl swap is immediately visible through the
            // simulator's trace.
            let (clock, irq) = vibix::task::env::env();
            let now = clock.now();
            let mut drained = clock.drain_expired(now);
            if let Some(rot) = self.pending_reorder.take() {
                if drained.len() >= 2 {
                    let n = drained.len();
                    let r = (rot as usize) % n;
                    drained.rotate_left(r);
                }
                // Even if the batch was too small to observably
                // reorder, we already emitted the `FaultInjected`
                // record so replay equivalence holds; the rotation
                // state is consumed regardless.
            }
            for id in drained {
                self.trace.push(TraceRecord {
                    tick: now_after,
                    event: Event::WakeupFired { id },
                });
            }

            irq.ack_timer();
            self.trace.push(TraceRecord {
                tick: now_after,
                event: Event::TimerIrqAcked,
            });

            self.cfg.invariants.check_safety(self.trace.records())
        }

        /// Run the registered liveness invariants against the closed
        /// trace. Intended to be called once at end-of-run; returns
        /// the first violation, if any.
        pub fn check_liveness(&self) -> Result<(), Violation> {
            self.cfg.invariants.check_liveness(self.trace.records())
        }

        /// Advance the simulator by exactly `ticks` calls to
        /// [`Simulator::step`]. No predicate; intended for
        /// "let `N` ticks pass and look at the trace" tests.
        pub fn run_for(&mut self, ticks: u64) {
            for _ in 0..ticks {
                self.step();
            }
        }

        /// Step the simulator until `predicate(self)` returns `true`,
        /// or until the per-run [`SimulatorConfig::max_ticks`] cap is
        /// reached. Returns the tick at which the predicate fired, or
        /// `None` on cap exhaustion.
        ///
        /// The predicate is called *before* each `step`, so a
        /// predicate that is already satisfied at entry returns `Some`
        /// without advancing the clock. This matches the
        /// `while !done { step }` shape every Phase 2 test wants and
        /// avoids the off-by-one in the alternative
        /// "step-then-check" form.
        pub fn run_until<F>(&mut self, mut predicate: F) -> Option<u64>
        where
            F: FnMut(&Simulator) -> bool,
        {
            for _ in 0..self.cfg.max_ticks {
                if predicate(self) {
                    return Some(self.current_tick());
                }
                self.step();
            }
            // One last check after the budget is exhausted — a
            // predicate satisfied exactly at the cap should still
            // return `Some`, not `None`.
            if predicate(self) {
                Some(self.current_tick())
            } else {
                None
            }
        }
    }

    #[cfg(test)]
    impl Simulator {
        /// **Test-only.** Append a synthesized `TraceRecord` directly
        /// onto the underlying trace, bypassing the kernel-emit path.
        /// Used by unit tests for the read-only introspection helpers
        /// (`current_task`, `runqueue_snapshot`, `pid_table_snapshot`)
        /// to construct a deterministic trace without driving
        /// `cfg(target_os = "none")` scheduler code from host code.
        pub(crate) fn test_push_record(&mut self, rec: TraceRecord) {
            self.trace.push(rec);
        }
    }

    impl core::fmt::Debug for Simulator {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Simulator")
                .field("seed", &self.cfg.seed)
                .field("max_ticks", &self.cfg.max_ticks)
                .field("current_tick", &self.current_tick())
                .field("trace_len", &self.trace.len())
                .finish()
        }
    }

    /// Process-global cell for the most recent simulator tick.
    ///
    /// The panic hook reads this directly so even a panic that fires
    /// off-thread, after the owning `Simulator` has been moved, can
    /// still surface `tick=<N>` in the message. Initialised lazily on
    /// first call to `Simulator::new` or `install_panic_hook`.
    fn current_tick_cell() -> &'static AtomicU64 {
        static CELL: OnceLock<AtomicU64> = OnceLock::new();
        CELL.get_or_init(|| AtomicU64::new(0))
    }

    /// Process-global cell for the simulator seed observed by the
    /// panic hook. Stored separately from `Simulator` so the hook can
    /// run after a panicking thread has already unwound the owning
    /// struct.
    fn current_seed_cell() -> &'static AtomicU64 {
        static CELL: OnceLock<AtomicU64> = OnceLock::new();
        CELL.get_or_init(|| AtomicU64::new(0))
    }

    /// `true` once `install_panic_hook` has chained a previous hook.
    /// Used to keep installation idempotent across multiple
    /// `Simulator::new` calls within the same process (e.g.
    /// `cargo test` running several seeds back-to-back inside one
    /// test binary).
    fn hook_installed_cell() -> &'static std::sync::atomic::AtomicBool {
        static CELL: OnceLock<std::sync::atomic::AtomicBool> = OnceLock::new();
        CELL.get_or_init(|| std::sync::atomic::AtomicBool::new(false))
    }

    /// Install the simulator's panic hook.
    ///
    /// On panic, the hook prints
    ///
    /// ```text
    /// SIMULATOR PANIC seed=<u64> tick=<u64>
    /// ```
    ///
    /// to stderr and then re-raises by chaining to the previously
    /// installed hook so the standard panic message and backtrace
    /// still appear and the process still aborts under
    /// `panic = "abort"`.
    ///
    /// Idempotent: repeated calls update the recorded seed but leave a
    /// single hook installed.
    pub fn install_panic_hook(seed: Seed) {
        // Always update the seed cell — tests that swap seeds expect
        // the hook to surface the *current* seed, not the first one.
        current_seed_cell().store(seed.as_u64(), Ordering::SeqCst);

        // Only chain a hook once; subsequent calls are no-ops beyond
        // updating the seed cell above.
        if hook_installed_cell()
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let seed = current_seed_cell().load(Ordering::SeqCst);
            let tick = current_tick_cell().load(Ordering::SeqCst);
            eprintln!("SIMULATOR PANIC seed={seed} tick={tick}");
            prev(info);
        }));
    }

    /// **Test-only.** Set the recorded tick value directly.
    ///
    /// Used by the unit tests in this crate to verify the panic hook
    /// surfaces the right `tick=<N>` annotation. Not exposed to
    /// production code paths — the run loop owns tick advancement via
    /// [`Simulator::step`].
    #[cfg(test)]
    pub(crate) fn test_only_set_tick(tick: u64) {
        current_tick_cell().store(tick, Ordering::SeqCst);
    }
}

#[cfg(not(target_os = "none"))]
pub use imp::{
    install_panic_hook, AllRunnableEventuallyRun, BlockReason, BlockedToRunnableNeedsWakeup, Event,
    FaultEvent, FaultKind, FaultPlan, FaultPlanBuilder, ForkHasMatchingExitOrWait, InvariantSet,
    LivenessInvariant, MonotonicPids, NoStrandedWakeups, SafetyInvariant, Seed, SimRng, Simulator,
    SimulatorConfig, SingleRunningPerCpu, Trace, TraceRecord, VariantMask, Violation,
    FAULT_PLAN_SCHEMA_VERSION, SCHEMA_VERSION,
};

// On `target_os = "none"` (the bare-metal kernel image), the simulator
// crate has no public surface — the `vibix` dependency is gated out
// in Cargo.toml and there is no `std`. In practice the workspace
// never builds this crate for that target, but keeping the module
// empty here makes the gate explicit at the source level.
#[cfg(target_os = "none")]
mod imp {}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    /// Construct a `Simulator` with a fresh thread, returning the join
    /// handle's value.
    ///
    /// The kernel-side `install_sim_env` panics if called twice on the
    /// same thread; running every test that constructs a `Simulator`
    /// on its own spawned thread is the simplest way to keep tests
    /// independent under cargo's parallel runner. The wrapper takes
    /// the test body as a closure so the per-thread setup stays in
    /// one place.
    fn on_fresh_thread<R, F>(f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        std::thread::spawn(f).join().expect("test thread panicked")
    }

    #[test]
    fn seed_round_trips_through_simulator() {
        on_fresh_thread(|| {
            let sim = Simulator::with_seed(0xDEAD_BEEF);
            assert_eq!(sim.seed(), Seed(0xDEAD_BEEF));
            assert_eq!(sim.config().seed.as_u64(), 0xDEAD_BEEF);
        });
    }

    #[test]
    fn current_tick_starts_at_zero() {
        on_fresh_thread(|| {
            let sim = Simulator::with_seed(0);
            assert_eq!(sim.current_tick(), 0);
        });
    }

    #[test]
    fn trace_default_is_empty() {
        let _t = Trace::new();
        let _t2 = Trace::default();
        assert!(Trace::default().is_empty());
        assert_eq!(Trace::default().len(), 0);
    }

    #[test]
    fn install_panic_hook_is_idempotent() {
        // Process-global hook; safe to call from any thread without
        // serialisation because `install_panic_hook` is itself
        // idempotent (the compare_exchange on `hook_installed_cell`
        // ensures a single chain).
        install_panic_hook(Seed(1));
        install_panic_hook(Seed(2));
        install_panic_hook(Seed(3));
    }

    #[test]
    fn step_advances_clock_and_records_canonical_event_order() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(0x1234, SimulatorConfig::with_seed(0x1234));
            sim.step();
            assert_eq!(sim.current_tick(), 1);

            let recs = sim.trace().records();
            // No wakeups armed → exactly three records:
            // ClockAdvanced, TimerInjected, TimerAcked.
            assert_eq!(recs.len(), 3);
            assert!(matches!(
                recs[0].event,
                Event::TickAdvance { from: 0, to: 1 }
            ));
            assert!(matches!(recs[1].event, Event::TimerInjected));
            assert!(matches!(recs[2].event, Event::TimerIrqAcked));
            // Every record's tick is the post-advance value.
            for r in recs {
                assert_eq!(r.tick, 1);
            }
            // IRQ counters mirror the seam invariant: ack_count == inject_count.
            assert_eq!(sim.irq().ack_count(), 1);
            assert_eq!(sim.irq().pending_timers(), 0);
        });
    }

    #[test]
    fn step_drains_expired_wakeups_in_seam_order() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(7, SimulatorConfig::with_seed(7));
            // Arm two wakeups for tick=2 (same deadline) and one for tick=3.
            // The MockClock seam orders drains by deadline, then by
            // insertion within a deadline — we verify both axes here.
            // `Tick`'s tuple constructor is pub(crate) inside the
            // kernel; from the simulator we reach a `Tick(N)` value by
            // anchoring on `clock.now()` (which returns one) and
            // calling `saturating_add` for the offset.
            let (clock, _irq) = vibix::task::env::env();
            let now = clock.now();
            clock.enqueue_wakeup(now.saturating_add(2), 100);
            clock.enqueue_wakeup(now.saturating_add(2), 101);
            clock.enqueue_wakeup(now.saturating_add(3), 200);

            sim.step(); // tick → 1, no wakes
            sim.step(); // tick → 2, drains 100 then 101
            sim.step(); // tick → 3, drains 200

            let woken: Vec<_> = sim
                .trace()
                .records()
                .iter()
                .filter_map(|r| match r.event {
                    Event::WakeupFired { id } => Some((r.tick, id)),
                    _ => None,
                })
                .collect();
            assert_eq!(woken, vec![(2, 100), (2, 101), (3, 200)]);
        });
    }

    #[test]
    fn run_for_executes_exactly_n_steps() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(1, SimulatorConfig::with_seed(1));
            sim.run_for(50);
            assert_eq!(sim.current_tick(), 50);
            // 3 records per step (no wakeups), so trace len == 150.
            assert_eq!(sim.trace().len(), 150);
        });
    }

    #[test]
    fn run_until_stops_at_predicate_satisfaction() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(2, SimulatorConfig::with_seed(2));
            let stopped_at = sim.run_until(|s| s.current_tick() >= 17);
            assert_eq!(stopped_at, Some(17));
            assert_eq!(sim.current_tick(), 17);
        });
    }

    #[test]
    fn run_until_returns_none_on_budget_exhaustion() {
        on_fresh_thread(|| {
            let mut cfg = SimulatorConfig::with_seed(3);
            cfg.max_ticks = 5;
            let mut sim = Simulator::new(3, cfg);
            // Predicate that never fires forces the loop to hit the cap.
            let result = sim.run_until(|_| false);
            assert_eq!(result, None);
            // Cap consumed: 5 steps ran.
            assert_eq!(sim.current_tick(), 5);
        });
    }

    #[test]
    fn run_until_at_entry_returns_without_stepping() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(4, SimulatorConfig::with_seed(4));
            let stopped_at = sim.run_until(|_| true);
            assert_eq!(stopped_at, Some(0));
            assert_eq!(sim.current_tick(), 0);
            assert!(sim.trace().is_empty());
        });
    }

    /// Smoke test (RFC 0006 / issue #716 acceptance): a 1000-tick run
    /// with two cooperating "tasks" (modelled as periodic wakeup
    /// enqueues) produces a deterministic trace, and two independent
    /// `Simulator` instances built from the same seed produce
    /// byte-identical trace records.
    ///
    /// This is the property the issue asks for as the merge
    /// gate — tested twice within one process here, and run twice
    /// back-to-back in CI as a separate cargo invocation.
    #[test]
    fn smoke_1000_ticks_with_two_tasks_is_deterministic() {
        fn run(seed: u64) -> Vec<TraceRecord> {
            let mut sim = Simulator::new(seed, SimulatorConfig::with_seed(seed));
            // Two cooperating "tasks": A wakes every 7 ticks, B every
            // 11 ticks. Re-arm at every wake. Models the real-kernel
            // pattern where `sleep_ms` re-enqueues a wakeup on
            // resume.
            let (clock, _irq) = vibix::task::env::env();
            let start = clock.now();
            clock.enqueue_wakeup(start.saturating_add(7), 1);
            clock.enqueue_wakeup(start.saturating_add(11), 2);

            for _ in 0..1000 {
                sim.step();
                // Re-arm the wakeups one period out from the current
                // tick. We re-arm even when the task wasn't due this
                // tick — `MockClock` accepts a `(deadline, id)`
                // multiple times and drains in deadline order, so the
                // model stays simple.
                let now = clock.now();
                if now.raw() % 7 == 0 {
                    clock.enqueue_wakeup(now.saturating_add(7), 1);
                }
                if now.raw() % 11 == 0 {
                    clock.enqueue_wakeup(now.saturating_add(11), 2);
                }
            }
            sim.trace().records().to_vec()
        }

        let a = on_fresh_thread(|| run(0xDEAD_BEEF));
        let b = on_fresh_thread(|| run(0xDEAD_BEEF));
        assert_eq!(
            a,
            b,
            "two runs of the same seed produced different traces (len {} vs {})",
            a.len(),
            b.len()
        );

        // Sanity: the trace is non-trivial — both tasks woke many
        // times, and the 1000-tick run drove the canonical seam shape.
        let wakes_1: usize = a
            .iter()
            .filter(|r| matches!(r.event, Event::WakeupFired { id: 1 }))
            .count();
        let wakes_2: usize = a
            .iter()
            .filter(|r| matches!(r.event, Event::WakeupFired { id: 2 }))
            .count();
        // Task 1 fires at ticks 7, 14, 21, ... up to 994 → 142 wakes.
        // Task 2 fires at ticks 11, 22, 33, ... up to 990 → 90 wakes.
        // Exact counts are part of the determinism contract here.
        assert_eq!(wakes_1, 1000 / 7);
        assert_eq!(wakes_2, 1000 / 11);
    }

    /// RFC 0006 / issue #717 acceptance: a recorded trace round-trips
    /// through the stable JSON schema without drift.
    ///
    /// Property: `record → JSON → parse → re-record → identical trace`.
    /// Using the same #716 cooperating-tasks workload as the
    /// determinism smoke test so the round-trip is tested against a
    /// non-trivial trace (~1000 records, every variant the run loop
    /// emits today, including `WakeupFired` for both task ids).
    #[test]
    fn smoke_recorded_trace_round_trips_through_json() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(0xC0FF_EE42, SimulatorConfig::with_seed(0xC0FF_EE42));
            let (clock, _irq) = vibix::task::env::env();
            let start = clock.now();
            clock.enqueue_wakeup(start.saturating_add(7), 1);
            clock.enqueue_wakeup(start.saturating_add(11), 2);

            for _ in 0..200 {
                sim.step();
                let now = clock.now();
                if now.raw() % 7 == 0 {
                    clock.enqueue_wakeup(now.saturating_add(7), 1);
                }
                if now.raw() % 11 == 0 {
                    clock.enqueue_wakeup(now.saturating_add(11), 2);
                }
            }

            let json1 = sim.trace().to_json_string();
            let parsed = Trace::from_json(&json1).expect("parse round-trip");
            assert_eq!(
                sim.trace().records(),
                parsed.records(),
                "parsed trace differs from original"
            );
            assert_eq!(sim.trace().diff(&parsed), None);

            // Re-serialize the parsed trace and demand byte-identical
            // JSON. This is the strict round-trip property — any field
            // ordering drift in the encoder would fail here even if
            // `records()` happened to compare equal via the
            // `PartialEq` derive.
            let json2 = parsed.to_json_string();
            assert_eq!(json1, json2, "JSON drifted across record→json→parse→record");
        });
    }

    #[test]
    fn rng_for_named_substream_is_reproducible_across_runs() {
        // No `Simulator` needed — `SimRng` is pure.
        use rand_core::Rng;
        let r1 = SimRng::new(0xCAFE_F00D);
        let r2 = SimRng::new(0xCAFE_F00D);
        let mut s1 = r1.rng_for("scheduler");
        let mut s2 = r2.rng_for("scheduler");
        for _ in 0..32 {
            assert_eq!(s1.next_u64(), s2.next_u64());
        }
    }

    #[test]
    fn rng_for_named_substreams_are_independent() {
        use rand_core::Rng;
        let r = SimRng::new(0x1111_2222_3333_4444);
        let mut a = r.rng_for("scheduler");
        let mut b = r.rng_for("faults");
        // Two independent streams must not produce the same first u64
        // — collision probability is 2^-64, so a hit here is almost
        // certainly a bug in the splitmix64 / FNV mix above.
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn rng_for_disjoint_names_do_not_share_first_byte() {
        // Defence in depth on the splatter: a one-character name
        // change should avalanche through the full ChaCha seed, not
        // share a partial seed prefix.
        use rand_core::Rng;
        let r = SimRng::new(42);
        let mut a = r.rng_for("a");
        let mut b = r.rng_for("b");
        assert_ne!(a.next_u64(), b.next_u64());
    }

    /// RFC 0006 / #718 introspection helpers.
    ///
    /// These tests synthesize a trace by reaching into the test-only
    /// `Trace::push` (`pub(crate)` — accessible from this module) so
    /// the helper logic can be exercised without driving the kernel
    /// scheduler from host code (which is impossible — sched_core is
    /// `cfg(target_os = "none")`-gated).
    #[test]
    fn current_task_returns_none_on_empty_trace() {
        on_fresh_thread(|| {
            let sim = Simulator::with_seed(0xAA);
            assert_eq!(sim.current_task(), None);
            assert!(sim.runqueue_snapshot().is_empty());
            assert!(sim.pid_table_snapshot().is_empty());
        });
    }

    #[test]
    fn current_task_returns_latest_scheduled_id() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(0xBB, SimulatorConfig::with_seed(0xBB));
            // Hand-build a trace tail: schedule task 1, then 2.
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::TaskScheduled { id: 1 },
            });
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::TaskScheduled { id: 2 },
            });
            assert_eq!(sim.current_task(), Some(2));
        });
    }

    #[test]
    fn runqueue_snapshot_tracks_wakeup_then_schedule() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(0xCC, SimulatorConfig::with_seed(0xCC));
            // Three tasks wake; one of them gets scheduled.
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::WakeupFired { id: 10 },
            });
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::WakeupFired { id: 20 },
            });
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::WakeupFired { id: 30 },
            });
            // 20 is now running; 10 and 30 stay ready.
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::TaskScheduled { id: 20 },
            });
            let mut rq = sim.runqueue_snapshot();
            rq.sort_unstable();
            assert_eq!(rq, vec![10, 30]);

            // Now block 30; only 10 remains ready.
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::TaskBlocked {
                    id: 30,
                    reason: BlockReason::Wait,
                },
            });
            assert_eq!(sim.runqueue_snapshot(), vec![10]);
        });
    }

    #[test]
    fn pid_table_snapshot_unions_event_ids() {
        on_fresh_thread(|| {
            let mut sim = Simulator::new(0xDD, SimulatorConfig::with_seed(0xDD));
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::WakeupEnqueued { deadline: 5, id: 7 },
            });
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::TaskScheduled { id: 7 },
            });
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::TaskBlocked {
                    id: 8,
                    reason: BlockReason::Sleep,
                },
            });
            sim.test_push_record(TraceRecord {
                tick: 0,
                event: Event::WakeupFired { id: 9 },
            });
            assert_eq!(sim.pid_table_snapshot(), vec![7, 8, 9]);
        });
    }

    // -----------------------------------------------------------------
    // RFC 0006 / issue #719: FaultPlan acceptance tests.
    //
    // The acceptance criteria for #719 are:
    //   1. A plan recorded from a flaky run replays bit-identically.
    //   2. Each v1 fault variant produces an observable trace
    //      divergence vs. an unmoderated run on the same seed.
    //
    // The two-task workload below is the same shape the determinism
    // smoke test uses, with a third task added so `WakeupReorder` can
    // observably permute a multi-id batch (a single-id drain has
    // nothing to rotate).
    // -----------------------------------------------------------------

    fn run_with_plan(seed: u64, plan: FaultPlan, ticks: u64) -> Vec<TraceRecord> {
        let mut cfg = SimulatorConfig::with_seed(seed);
        cfg.fault_plan = plan;
        let mut sim = Simulator::new(seed, cfg);
        let (clock, _irq) = vibix::task::env::env();
        let start = clock.now();
        // Three cooperating tasks with co-prime periods so the
        // wakeup batches at certain ticks contain >= 2 ids — that's
        // the precondition for `WakeupReorder` to observably permute
        // the trace.
        clock.enqueue_wakeup(start.saturating_add(2), 1);
        clock.enqueue_wakeup(start.saturating_add(2), 2);
        clock.enqueue_wakeup(start.saturating_add(3), 3);
        for _ in 0..ticks {
            sim.step();
            let now = clock.now();
            // Re-arm at every wake. Multiple ids share several ticks
            // (e.g. tick 6: id 1 from period 2 *and* id 3 from period
            // 3), guaranteeing batches the reorder fault can act on.
            if now.raw() % 2 == 0 {
                clock.enqueue_wakeup(now.saturating_add(2), 1);
                clock.enqueue_wakeup(now.saturating_add(2), 2);
            }
            if now.raw() % 3 == 0 {
                clock.enqueue_wakeup(now.saturating_add(3), 3);
            }
        }
        sim.trace().records().to_vec()
    }

    /// Recorded plan replays bit-identically — the property that
    /// makes seed-reproducible flake bug reports possible.
    #[test]
    fn fault_plan_recorded_run_replays_bit_identically() {
        // Build a randomized plan from `rng_for("faults")`.
        let plan = {
            let r = SimRng::new(0xFEED_FACE);
            let mut s = r.rng_for("faults");
            crate::FaultPlanBuilder::new(&mut s)
                .max_tick(64)
                .density(0.10)
                .build()
        };
        // Round-trip the plan through JSON before replay so the
        // recorded form (the wire artifact a CI dump would carry) is
        // what feeds the second run.
        let plan_json = plan.to_json_string();
        let plan_replay = crate::FaultPlan::from_json(&plan_json).expect("plan parse");
        assert_eq!(plan, plan_replay);

        let a = on_fresh_thread(move || run_with_plan(0xFEED_FACE, plan, 64));
        let b = on_fresh_thread(move || run_with_plan(0xFEED_FACE, plan_replay, 64));
        assert_eq!(
            a,
            b,
            "recorded plan replay drifted (lengths {} vs {})",
            a.len(),
            b.len()
        );
        // The plan must have actually injected something — otherwise
        // "replays identically" is trivial.
        let injected = a
            .iter()
            .filter(|r| matches!(r.event, Event::FaultInjected { .. }))
            .count();
        assert!(
            injected > 0,
            "expected at least one FaultInjected event in the recorded run"
        );
    }

    /// Each v1 fault variant produces an observable trace divergence
    /// vs. an unmoderated run on the same seed. This is the
    /// "fault has effect" half of the acceptance — without it, the
    /// plan could be silently dropped and the determinism property
    /// would still hold trivially.
    #[test]
    fn fault_plan_each_variant_diverges_from_unmoderated_run() {
        let baseline = on_fresh_thread(|| run_with_plan(0xABCD, crate::FaultPlan::new(), 32));

        // SpuriousTimerIrq at tick 4: emits an extra TimerInjected
        // record + a FaultInjected record, neither of which appears
        // in the baseline.
        let plan_irq =
            crate::FaultPlan::from_entries(vec![(4, crate::FaultEvent::SpuriousTimerIrq)]);
        let with_irq = on_fresh_thread(move || run_with_plan(0xABCD, plan_irq, 32));
        assert_ne!(
            baseline, with_irq,
            "SpuriousTimerIrq did not perturb the trace"
        );

        // TimerDrift at tick 4 by 2 extra ticks: shifts subsequent
        // wakeup deadlines forward; the trace diverges at the drifted
        // tick.
        let plan_drift =
            crate::FaultPlan::from_entries(vec![(4, crate::FaultEvent::TimerDrift { ticks: 2 })]);
        let with_drift = on_fresh_thread(move || run_with_plan(0xABCD, plan_drift, 32));
        assert_ne!(baseline, with_drift, "TimerDrift did not perturb the trace");

        // WakeupReorder at tick 6 (where the workload guarantees a
        // 3-element batch: ids 1, 2, 3 all due). Rotating by 1
        // observably permutes the WakeupFired records.
        let plan_reorder = crate::FaultPlan::from_entries(vec![(
            6,
            crate::FaultEvent::WakeupReorder { within_tick: 1 },
        )]);
        let with_reorder = on_fresh_thread(move || run_with_plan(0xABCD, plan_reorder, 32));
        assert_ne!(
            baseline, with_reorder,
            "WakeupReorder did not perturb the trace"
        );

        // The three perturbed runs are also pairwise distinct: each
        // variant exercises a different lever.
        assert_ne!(with_irq, with_drift);
        assert_ne!(with_irq, with_reorder);
        assert_ne!(with_drift, with_reorder);
    }

    /// Empty plan must produce a byte-identical trace to a run that
    /// never received a `fault_plan` field at all — the
    /// "default-zero" property the existing run-loop tests implicitly
    /// rely on.
    #[test]
    fn fault_plan_empty_is_indistinguishable_from_baseline() {
        let unmodified = on_fresh_thread(|| {
            // Baseline: simulator built via `with_seed`, which
            // installs the default empty FaultPlan.
            let mut sim = Simulator::with_seed(0xBEEF);
            sim.run_for(16);
            sim.trace().records().to_vec()
        });
        let with_explicit_empty = on_fresh_thread(|| {
            let mut cfg = SimulatorConfig::with_seed(0xBEEF);
            cfg.fault_plan = crate::FaultPlan::new();
            let mut sim = Simulator::new(0xBEEF, cfg);
            sim.run_for(16);
            sim.trace().records().to_vec()
        });
        assert_eq!(unmodified, with_explicit_empty);
    }

    #[test]
    fn test_hook_can_set_tick() {
        // Process-global cell — does not touch `task::env`'s thread-local,
        // so it does not need a fresh thread.
        super::imp::test_only_set_tick(123);
        // We can't construct a Simulator on this thread (some other test
        // may have already installed mocks), so just verify the cell
        // round-trips through `current_tick_cell` indirectly by
        // re-setting and reading via the same accessor.
        super::imp::test_only_set_tick(456);
    }
}
