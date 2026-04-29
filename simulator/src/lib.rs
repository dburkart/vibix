//! Host-side DST simulator skeleton (RFC 0006).
//!
//! This crate is the host-only driver that consumes the `sched-mock`
//! seam landed in [RFC 0005](../../../docs/RFC/0005-scheduler-irq-seam.md)
//! and converts today's flaky concurrency bugs into reproducible
//! `cargo test -- --seed=0xDEADBEEF` failures.
//!
//! Issue #715 ships the **skeleton only**: the public type names, a
//! diagnostic panic hook, and a `replay` binary stub. None of the types
//! here have real bodies yet — every `Simulator::run`, `Trace` record,
//! and `FaultPlan` interaction lands in follow-up issues:
//!
//! - #716 — run loop + `Simulator::with_seed(...).run(max_ticks)`.
//! - #717 — `(Tick, Event)` trace recorder + JSON dump.
//! - #718 — `sched_mock_trace!` macro + kernel-side emit points.
//! - #722 — invariant + liveness checkers.
//! - #723 — CI sweep (per-PR + nightly seed exploration).
//!
//! The deliberate emptiness here is the point: subsequent PRs land
//! without colliding on workspace plumbing or panic-hook wiring, and
//! the existing `host build (sched-mock)` CI job already exercises
//! the host-target build path the simulator depends on.
//!
//! # Determinism contract
//!
//! Every public surface in this crate must keep the simulator
//! byte-reproducible from `(seed, git commit, toolchain)` alone. That
//! contract is enforced workspace-wide by `clippy.toml` forbidding
//! `std::collections::HashMap` / `HashSet`, by the dated nightly pin
//! in `rust-toolchain.toml`, and by the kernel-side nm-check that
//! keeps `MockClock` / `MockTimerIrq` symbols out of release builds.
//! New types added here should reach for `BTreeMap` / `BTreeSet`, or
//! seeded `hashbrown::HashMap` with an explicit hasher — never
//! `std`'s default-hashed maps.

#![cfg_attr(not(test), deny(unsafe_code))]
#![warn(missing_docs)]

#[cfg(not(target_os = "none"))]
mod imp {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

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
    /// Fields beyond `seed` (max-tick budget, fault plan, invariant
    /// set, trace dump path, ...) land in follow-up issues; this stub
    /// only carries enough to thread the seed through.
    #[derive(Clone, Debug)]
    pub struct SimulatorConfig {
        /// Master seed for the run.
        pub seed: Seed,
    }

    impl SimulatorConfig {
        /// Construct a config from a raw `u64` seed.
        pub fn with_seed(seed: u64) -> Self {
            Self { seed: Seed(seed) }
        }
    }

    /// A `(Tick, Event)` trace stream emitted by a simulator run.
    ///
    /// The on-wire shape lands in #717; today this is an opaque empty
    /// container so downstream issues can plumb `Simulator::run` ->
    /// `Trace` without a name change later.
    #[derive(Clone, Debug, Default)]
    pub struct Trace {
        // Intentionally private. Issue #717 fills this in with a
        // `Vec<TraceRecord>` carrying serde-serializable `Event`
        // variants — keeping the field private now means that
        // `serde::Serialize` derive doesn't leak through public
        // re-exports of `Trace` in the meantime.
        _private: (),
    }

    impl Trace {
        /// Construct an empty trace.
        pub fn new() -> Self {
            Self { _private: () }
        }
    }

    /// Host-side deterministic simulator skeleton.
    ///
    /// The real run loop wires `MockClock` + `MockTimerIrq` into
    /// [`vibix::task`] and steps the kernel one tick at a time; that
    /// lands in #716. This stub exists so the panic hook and the
    /// `replay` binary can refer to a real type today.
    #[derive(Debug)]
    pub struct Simulator {
        cfg: SimulatorConfig,
        /// The simulated tick count. The panic hook reads this through
        /// the same atomic, so non-`Simulator` paths (e.g. a panicking
        /// background thread) can still report the last-known tick.
        current_tick: &'static AtomicU64,
    }

    impl Simulator {
        /// Construct a simulator bound to `seed`, installing the
        /// process-global panic hook (idempotent — last installer
        /// wins, see [`install_panic_hook`]).
        ///
        /// The constructor is the documented hook-installation site
        /// in RFC 0006 §"Failing-seed-to-repro path"; tests that need
        /// the hook without an entire simulator should call
        /// [`install_panic_hook`] directly.
        pub fn with_seed(seed: u64) -> Self {
            let cfg = SimulatorConfig::with_seed(seed);
            let current_tick = current_tick_cell();
            current_tick.store(0, Ordering::SeqCst);
            install_panic_hook(Seed(seed));
            Self { cfg, current_tick }
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
        /// Today this is always `0` — the run loop in #716 is what
        /// advances it. Exposed now so downstream code (replay
        /// binary, panic hook) can refer to a stable accessor.
        pub fn current_tick(&self) -> u64 {
            self.current_tick.load(Ordering::SeqCst)
        }
    }

    /// Process-global cell for the most recent simulator tick.
    ///
    /// The panic hook reads this directly so even a panic that fires
    /// off-thread, after the owning `Simulator` has been moved, can
    /// still surface `tick=<N>` in the message. Initialised lazily on
    /// first call to `Simulator::with_seed` or `install_panic_hook`.
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
    /// `Simulator::with_seed` calls within the same process (e.g.
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
    /// to stderr (the `VIBIX_SIM_SEED=` annotation form lands in #717
    /// once the trace path is plumbed; today the simpler diagnostic is
    /// what issue #715 asks for) and then re-raises by chaining to the
    /// previously-installed hook so the standard panic message and
    /// backtrace still appear and the process still aborts under
    /// `panic = "abort"`.
    ///
    /// Idempotent: repeated calls update the recorded seed but leave a
    /// single hook installed. This matches RFC 0006's "last installer
    /// wins" rule and keeps the hook stack from growing unboundedly
    /// inside a `cargo test` run that constructs many `Simulator`
    /// instances.
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
            // Use `eprintln!` so the diagnostic shows up on the same
            // stream as the standard panic message that the chained
            // `prev` hook will print next; downstream tooling greps
            // stderr for the `SIMULATOR PANIC` prefix.
            eprintln!("SIMULATOR PANIC seed={seed} tick={tick}");
            prev(info);
        }));
    }

    /// **Test-only.** Set the recorded tick value directly.
    ///
    /// Used by the unit tests in this crate to verify the panic hook
    /// surfaces the right `tick=<N>` annotation. Not exposed to
    /// production code paths — the run loop in #716 owns tick
    /// advancement via `Simulator::run`.
    #[cfg(test)]
    pub(crate) fn test_only_set_tick(tick: u64) {
        current_tick_cell().store(tick, Ordering::SeqCst);
    }
}

#[cfg(not(target_os = "none"))]
pub use imp::{install_panic_hook, Seed, Simulator, SimulatorConfig, Trace};

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

    #[test]
    fn seed_round_trips_through_simulator() {
        let sim = Simulator::with_seed(0xDEAD_BEEF);
        assert_eq!(sim.seed(), Seed(0xDEAD_BEEF));
        assert_eq!(sim.config().seed.as_u64(), 0xDEAD_BEEF);
    }

    #[test]
    fn current_tick_starts_at_zero() {
        let sim = Simulator::with_seed(0);
        assert_eq!(sim.current_tick(), 0);
    }

    #[test]
    fn trace_default_is_empty() {
        // Today `Trace` is empty by construction. This test exists so
        // that the schema-bearing PR (#717) has to update an
        // assertion when it adds real fields, surfacing the change in
        // review.
        let _t = Trace::new();
        let _t2 = Trace::default();
    }

    #[test]
    fn install_panic_hook_is_idempotent() {
        // Multiple installs must not stack hooks. We can't observe
        // the hook stack directly, but we can at least verify the
        // function is callable repeatedly with different seeds
        // without panicking or deadlocking.
        install_panic_hook(Seed(1));
        install_panic_hook(Seed(2));
        install_panic_hook(Seed(3));
    }

    #[test]
    fn panic_hook_records_latest_seed() {
        // The hook always reports the *current* seed, not the first
        // one installed. The hook chaining is exercised end-to-end
        // by manual repro; this test pins the seed-cell behaviour.
        install_panic_hook(Seed(0xAAAA));
        install_panic_hook(Seed(0xBBBB));
        // Construct a simulator after — `with_seed` updates the cell
        // again, mirroring the real failing-seed-to-repro flow.
        let sim = Simulator::with_seed(0xCCCC);
        assert_eq!(sim.seed().as_u64(), 0xCCCC);
    }

    #[test]
    fn test_hook_can_set_tick() {
        let sim = Simulator::with_seed(7);
        super::imp::test_only_set_tick(42);
        assert_eq!(sim.current_tick(), 42);
    }
}
