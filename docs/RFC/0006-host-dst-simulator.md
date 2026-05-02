---
rfc: 0006
title: Host-Side Deterministic Simulator (DST Phase 2)
status: Accepted
created: 2026-04-27
---

# RFC 0006: Host-Side Deterministic Simulator (DST Phase 2)

## Abstract

Build a host-side `simulator/` crate that consumes the scheduler / IRQ
seam landed in [RFC 0005](0005-scheduler-irq-seam.md) to drive the
vibix kernel's task subsystem one tick at a time under a seeded
`Clock` + `TimerIrq` pair, exposing a state-machine model interface
that turns today's flaky concurrency bugs into reproducible
`cargo test -- --seed=0xDEADBEEF` failures. Phase 2 ships the
single-binary `cfg(host) + feature = "sched-mock"` architecture, a
linear tick-by-tick driver, a `(Tick, Event)` trace stream, and a
fault-injection scope limited to timer-IRQ scheduling and existing
seam-modelable surfaces. Hardware faults (`#PF`, `#GP`, `#DF`),
syscall-entry interposition, and IPI/SMP modeling are explicitly
deferred to Phase 2.1 follow-up RFCs.

## Motivation

[RFC 0005](0005-scheduler-irq-seam.md) shipped the seam on the promise
that *Phase 2 — the simulator that consumes the seam — converts flakes
into seeds*. That promise is now overdue. Three open P0 flakes
collectively burn ~6–8 hours of CI wall-clock per retry under
`-Zbuild-std` + QEMU and currently can only be debugged by re-running
and hoping:

- **#501 — fork/exec/wait flakiness sprint** (long-running, primary
  justification for Phase 2 existing). The bug surface includes child
  exit-code racing the parent's `wait`, `exec` overlay racing
  signal delivery, and zombie reaping interleaved with timer ticks. A
  seeded simulator that drives `MockTimerIrq::inject_timer` between
  every scheduler step makes the offending interleaving observable
  rather than hypothesised.
- **#527 — residual ring3 user-stack `#PF` at rip=0x4002c6**. The
  fault location is stable; the *trigger* — which prior context-switch
  arrived where, and what ready-bank rotation produced the observed
  rip — is not. Replaying a candidate scheduler trace against a seed
  pins the trigger.
- **#478 — userspace init never emits "init: hello from pid 1" after
  IRETQ**. Either an IRETQ-sequencing race or a wakeup that never
  drained; both are observable as a state-machine trace that ends in
  `init` perpetually-blocked.

The seam alone is necessary but not sufficient. Without a host-side
driver that calls `MockClock::advance` / `MockTimerIrq::inject_timer`
in a *deliberately* exploratory pattern (seeded random, not just one
unit-test's manual sequence), every flake the seam *could* surface
still requires a human to write the exact tick-by-tick choreography
that reproduces it. The simulator is the loop that does this
exploration automatically.

Two adjacent RFCs already-in-flight depend on this:

- **#390 — concurrency stress** becomes deterministic stress: every
  failure is a seed.
- **#391 — property-based invariants** gains a stateful-model variant
  via `proptest-state-machine` over the simulator's `(Tick, Event)`
  trace.

Without Phase 2 those two suites duplicate driver infrastructure;
with Phase 2 they share it.

## Background

### Prior art surveyed

| Source | Lesson taken |
|---|---|
| TigerBeetle VOPR ([docs/internals/vopr.md](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md), [Tale Of Four Fuzzers](https://tigerbeetle.com/blog/2025-11-28-tale-of-four-fuzzers/)) | Single-thread, single-binary simulator stubs clock + network + disk. Reproducibility = `seed + git commit`. ~3.3 s of VOPR ≈ 39 min of real time. They later added Vörtex (intentionally non-deterministic, multi-language) on top — DST is a layer, not a complete strategy. |
| FoundationDB Flow simulator ([Will Wilson, Strange Loop 2014](https://www.youtube.com/watch?v=4fFDFbi3toc)) | DST works iff *every* nondeterminism source goes through the runtime. The cost of one escape hatch is the entire harness. They wrote the simulator first and debugged it for years before the DB existed. |
| sled simulation guide ([sled.rs/simulation.html](http://sled.rs/simulation.html)) | The `receive(msg, at) -> [(msg, dest)]` + `tick(at) -> [(msg, dest)]` state-machine shape is the canonical pattern. Periodic events become messages. |
| Polar Signals "DST in Rust: A Theater of State Machines" ([blog 2025-07-08](https://www.polarsignals.com/blog/posts/2025/07/08/dst-rust)) | Cautionary tale. Forcing all code into the state-machine model imposes real cognitive overhead; engineers route around it; the path of least resistance leaks logic into production drivers that escape DST. **Don't model what you don't have to.** |
| Tokio loom ([github.com/tokio-rs/loom](https://github.com/tokio-rs/loom)) | Exhaustive C11 memory-model permutation via dynamic partial order reduction. Sound but doesn't scale beyond small primitives. Wrong tool for whole-scheduler exploration; right inspiration for "swap types via cfg, not architecture." |
| AWS shuttle ([github.com/awslabs/shuttle](https://github.com/awslabs/shuttle)) | Randomized scheduler with probabilistic guarantees. Unsound but scales. *Most bugs caught in a few hundred iterations.* This is the iteration budget Phase 2 should target — not millions of seeds, hundreds-to-thousands. |
| Meta Hermit ([github.com/facebookexperimental/hermit](https://github.com/facebookexperimental/hermit)) | Syscall-interception determinism for unmodified Linux processes. Far too invasive for our needs — we own the kernel and have the seam. Useful counterpoint: the cost of "fully deterministic without source cooperation" is enormous. |
| Antithesis Determinator ([antithesis.com/blog/deterministic_hypervisor](https://antithesis.com/blog/deterministic_hypervisor/)) | Hypervisor-level determinism with full instruction replay. Overkill for a scheduler-decision harness — we don't need ring-3 instruction streams to be deterministic, only kernel scheduler decisions. |
| madsim ([github.com/madsim-rs/madsim](https://github.com/madsim-rs/madsim)) | Tokio-shaped runtime that's deterministic under a `MADSIM` cfg. Validates the cfg-gated-runtime-swap pattern as the right Rust idiom. |
| proptest-state-machine ([proptest-rs.github.io/proptest/proptest/state-machine.html](https://proptest-rs.github.io/proptest/proptest/state-machine.html)) | The standard Rust shape for stateful property tests: define a reference state machine, generate sequences of transitions, shrink failing sequences. Phase 2's external interface should be a `proptest` `ReferenceStateMachine` impl so #391 plugs in without bespoke glue. |

### The seam as it shipped (RFC 0005)

`kernel/src/task/env.rs` defines `Clock` and `TimerIrq` traits. The
production wire-up returns `(&'static dyn Clock, &'static dyn
TimerIrq)` from `task::env()`. Behind the `sched-mock` feature,
`MockClock` and `MockTimerIrq` already exist with the exact APIs
Phase 2 needs:

- `MockClock::new(seed: u64)` — seedable initial tick.
- `MockClock::tick()` / `MockClock::advance(n)` — explicit time
  progression (no implicit advance).
- `MockClock::pending_wakeups()` — introspection.
- `MockTimerIrq::inject_timer()` / `ack_count()` /
  `pending_timers()` — observable IRQ injection.

The nm-check guard (#669) statically forbids these symbols from
appearing in release ELFs. Phase 2 reuses these mocks directly —
this is defended in **§Design / Crate boundary** below.

### Discipline carried over from RFC 0005

> A `Clock` or `TimerIrq` trait method is added only when a second
> implementation actually needs it.

Phase 2 *is* the second implementation that the discipline anticipated.
This RFC is therefore where additions to the trait surface get
debated. We add **zero** new methods to `Clock` or `TimerIrq` in
Phase 2 v1 — `MockClock` + `MockTimerIrq` as shipped suffice for the
flakes we need to reproduce. New surfaces (page-fault injection,
syscall-entry hooks) are explicitly Phase 2.1 RFCs (§Open Questions).

## Design

### Overview

A new crate, `simulator/`, lives at the workspace root. It is built
**only** for the host triple (`cfg(not(target_os = "none"))`) and
links the `kernel` crate with `--features sched-mock` enabled. The
simulator binary is a normal `cargo test` /
`cargo run -p simulator` target — it never goes near `xtask build
--release` or QEMU.

```
vibix/
├── kernel/                 # existing (no_std, target_os = "none" for production)
├── simulator/              # NEW: host-only crate
│   ├── Cargo.toml          # depends on kernel with feature = "sched-mock"
│   ├── src/
│   │   ├── lib.rs          # Simulator, SimConfig, run loop
│   │   ├── trace.rs        # (Tick, Event) record + serialization
│   │   ├── faults.rs       # FaultPlan: timer-jitter / spurious-tick injection
│   │   ├── proptest_model.rs # ReferenceStateMachine impl for #391
│   │   └── bin/
│   │       └── replay.rs   # cargo run -p simulator --bin replay -- --seed=…
│   └── tests/              # integration tests reproducing #501 / #527 / #478
└── ...
```

### Host-target buildability of `kernel/` (resolves OS-engineer B1)

Before any of the architectural choices below mean anything, the
`kernel/` crate must compile for the host triple under `--features
sched-mock`. Today it does not — `kernel/src/task/env.rs` gates
`HwIrq`, `HW_IRQ`, `env()`, and `assert_production_env()` on
`#[cfg(target_os = "none")]`. Phase 2 commits to **option (a)** from
the OS-engineer review:

A parallel `#[cfg(all(not(target_os = "none"), feature =
"sched-mock"))] fn env()` is added to `kernel/src/task/env.rs`
returning the mock pair. The mocks are installed into a thread-local
`OnceCell<(&'static MockClock, &'static MockTimerIrq)>` by the
simulator's `Simulator::with_seed` constructor before the first
kernel call:

```rust
// kernel/src/task/env.rs, sched-mock + host build
#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
thread_local! {
    static SIM_ENV: core::cell::OnceCell<(&'static dyn Clock, &'static dyn TimerIrq)>
        = core::cell::OnceCell::new();
}

#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
pub fn env() -> (&'static dyn Clock, &'static dyn TimerIrq) {
    SIM_ENV.with(|c| *c.get().expect("simulator must call install_sim_env() first"))
}

#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]
pub fn install_sim_env(clock: &'static dyn Clock, irq: &'static dyn TimerIrq) {
    SIM_ENV.with(|c| c.set((clock, irq)).map_err(|_| "already installed").unwrap());
}
```

Thread-local (not global) because parallel `cargo test` workers
each get their own `Simulator` with their own seed — global state
would serialize them. Each test thread installs its own mock pair
once and panics if installed twice.

The follow-on work the buildability requires:

1. **Audit and gate `target_os = "none"` callers in
   `kernel/src/task/`, `kernel/src/sync/`, `kernel/src/signal/`,
   `kernel/src/syscall/`** under a parallel
   `cfg(all(not(target_os = "none"), feature = "sched-mock"))` arm
   that selects a host-buildable substitute. Concretely:
   - `IrqLock<T>` → `spin::Mutex<T>` on host (matches what
     `MockClock` already does, RFC 0005 wave 3).
   - `arch::ack_timer_irq()` is unreachable on host because
     `HwIrq` doesn't exist; only `MockTimerIrq::ack_timer` is
     callable. No substitute needed — the call site is reached only
     via `env()` which returns a mock.
   - Inline assembly (`cli`/`sti`/IRETQ etc.) is gated to
     `target_os = "none"` already; under `sched-mock` host build,
     the no-op host alternative is selected.
2. **A new CI job — `cargo build -p kernel --target
   x86_64-unknown-linux-gnu --features sched-mock`** — gates that
   the host build keeps compiling. It runs alongside the existing
   bare-metal build and the nm-check.

This is real engineering work, not RFC handwaving — Roadmap item 1
is rewritten below to land the host-buildability slice **before**
any simulator code exists, so the rest of Phase 2 builds on a
verified host-buildable kernel.

### IRQ-context invariants under host driver (resolves OS-engineer B2)

The simulator runs `kernel::task::preempt_tick()` from an ordinary
host thread; it is not in IRQ context. Two invariants must be
preserved:

1. **No re-entrancy of `preempt_tick`.** The simulator MUST NOT call
   `preempt_tick` recursively. The driver loop (§Driver loop)
   already has this property — it calls `preempt_tick` exactly once
   per outer-loop iteration, and the FaultPlan's `inject` step runs
   *before* that call returns to the loop top. If a future
   FaultPlan grows a callback that fires during
   `MockClock::drain_expired`, that callback MUST NOT call
   `preempt_tick`. Enforced by a `#[cfg(debug_assertions)]`
   re-entrancy guard inside `preempt_tick` itself, gated on
   `feature = "sched-mock"`:

   ```rust
   #[cfg(feature = "sched-mock")]
   thread_local! { static IN_PREEMPT_TICK: Cell<bool> = Cell::new(false); }
   #[cfg(feature = "sched-mock")]
   fn preempt_tick_guard() -> impl Drop {
       IN_PREEMPT_TICK.with(|f| {
           assert!(!f.get(), "preempt_tick is not re-entrant");
           f.set(true);
       });
       scopeguard::guard((), |_| IN_PREEMPT_TICK.with(|f| f.set(false)))
   }
   ```

2. **Host substitutes for IRQ-disable primitives must preserve
   ordering, not faithfully imitate IRQ masking.** `IrqLock` on host
   is `spin::Mutex` — fair-ish, contentious enough that lock-order
   violations surface as deadlocks. `cli`/`sti` becomes no-op
   (impossible to imitate without a kernel; the simulator's value is
   in checking ordering invariants the *seam* exposes, not in
   imitating ring-0 microarchitecture). The RFC commits to:
   - A list, in `docs/design/simulator.md`, of the IRQ-related
     primitives that have host substitutes and what those
     substitutes are. New primitives added to the kernel must
     declare a host substitute (or document why they're
     `target_os = "none"`-only and therefore unreachable under the
     simulator).
   - The simulator does **not** claim to find bugs that depend on
     real `cli`/`sti` semantics (e.g. interrupt-window races inside
     the timer ISR itself). Those remain in QEMU's domain. The
     simulator's contract is: *if a fault-injected sequence of
     scheduler-visible events would fail on real hardware, the
     simulator catches it.* Bugs whose trigger is below the seam
     (microarchitectural reordering, IRETQ stack-faulting, etc.)
     are out of scope and route to Phase 2.1's IDT/syscall-seam
     RFCs.

This boundary is what classifies #527 as deferred to Phase 2.1
(§Reproduction commitments below) — the residual `#PF` is
microarchitectural, below the seam.

### Event emit points (resolves OS-engineer B3)

The Event enum has two classes of variants distinguished by how
they're populated:

**(a) Observed-by-snapshot** (no kernel-side emit point needed):
- `TimerInjected`, `SpuriousTimerInjected`, `ClockAdvanced` — all
  driven by the simulator itself; emitted by the driver loop
  before/after stepping the kernel.
- `Switch { from, to }` — derived by snapshotting `current_id()`
  before and after each `preempt_tick` and emitting if it changed.
  No kernel-side call needed.
- `TaskReady`, `TaskBlocked` — derived by diffing
  `task::scheduler::ready_count()` /
  `task::scheduler::pending_blocked()` snapshots between ticks.
- `TaskWoken` — derived from the `Vec<TaskId>` returned by
  `MockClock::drain_expired`, which the simulator already calls
  through directly.

**(b) Emit-point-required** (kernel emits a tracing call):
- `Fork`, `Exec`, `Exit`, `Wait`, `SignalDelivered` — these are
  syscall-handler-level events. The kernel adds a single
  `sched_mock_trace!(Event::Fork { … })` macro at each emit point.

The macro expands to a no-op when `feature = "sched-mock"` is off
(zero-cost in production):

```rust
// kernel/src/sched_mock_trace.rs
#[cfg(feature = "sched-mock")]
#[macro_export]
macro_rules! sched_mock_trace {
    ($e:expr) => { $crate::sched_mock_trace::push($e) };
}
#[cfg(not(feature = "sched-mock"))]
#[macro_export]
macro_rules! sched_mock_trace {
    ($e:expr) => { () };
}

#[cfg(feature = "sched-mock")]
pub fn push(event: Event) { /* thread-local Vec, drained by simulator */ }
```

Verification that production-build emits zero code is by inspecting
generated assembly for at least one canonical site (`fork` syscall)
in the same CI job that runs the nm-check, and is gated as a
verifiable invariant rather than an assertion. Roadmap item 5 is
extended below to land this macro infrastructure alongside the
introspection helpers.

### Crate boundary: single-binary, sched-mock-feature, no separate kernel-FFI

This is the load-bearing architectural choice. The two viable shapes
are:

1. **Single binary, cfg-gated** (chosen). The simulator depends on
   `kernel` with `features = ["sched-mock"]` and calls the kernel's
   own `task::*` entry points directly. The simulator *is* a host
   build of the kernel, plus a driver loop.
2. **Separate binary with state-machine FFI**. The kernel exposes a
   stable `extern "C"` state-machine API (step / inject / observe);
   the simulator links against that ABI.

We pick (1) for these reasons:

- **The seam is already an in-Rust trait boundary.** Wrapping it in a
  C ABI just to put the simulator behind `dlopen` adds glue without
  adding isolation — the kernel and simulator are co-versioned and
  always built from the same git commit anyway (see Reproducibility
  Envelope below). FFI is a tax that buys nothing here.
- **Invariant-checking flexibility is higher inside the same binary.**
  The simulator can call `kernel::task::scheduler::introspect()`-shaped
  internal APIs (added behind `#[cfg(feature = "sched-mock")]`) to
  read kernel state directly into property-test assertions. Across
  an FFI boundary every introspection point becomes a serializable
  shape that has to be maintained.
- **Polar Signals' lesson applies.** A separate-binary state-machine
  API forces the kernel to be re-expressed *as* a state machine —
  exactly the cognitive-overhead trap their post-mortem warns
  against. The kernel stays kernel-shaped; the simulator is the
  state-machine view *over* the kernel, not a re-implementation.
- **Build complexity stays bounded.** One `Cargo.lock`, one
  `rust-toolchain.toml`, one `cargo test -p simulator`. No
  duplicate dependency trees.

The trade-off accepted: the simulator cannot run a *frozen* kernel
binary, only a host-rebuilt one. We do not need that capability —
every interesting question is "what does the kernel at this commit do
under this seed?", which is satisfied by `git checkout && cargo test
-p simulator -- --seed=…`.

### Reuse of existing `MockClock` / `MockTimerIrq` (vs. extending)

The RFC-0005 mocks are reused **as-is** in v1. They already provide:

- Seeded initial tick.
- Explicit `tick()` / `advance(n)` (no implicit time progression).
- `inject_timer()` returning observable injection counters.
- Internal `BTreeMap<deadline, Vec<TaskId>>` matching production
  semantics byte-for-byte (per RFC 0005's "drain order semantics
  identical").

The simulator wraps them in a `Simulator` struct that also owns the
trace recorder and the fault plan, but does not subclass or extend
the trait surface. **No new `Clock` / `TimerIrq` methods land in
Phase 2 v1.** Per the seam discipline, additions are debated when
needed — and the v1 flake set (§Reproduction commitments) is
expressible without them.

### The driver loop: linear tick-by-tick

```rust
// simulator/src/lib.rs (sketch)
pub struct Simulator {
    clock: &'static MockClock,
    irq:   &'static MockTimerIrq,
    rng:   ChaCha8Rng,           // re-seedable; named-stream design (§RNG)
    trace: TraceRecorder,
    plan:  FaultPlan,
    cfg:   SimConfig,
}

impl Simulator {
    pub fn run(&mut self, max_ticks: u64) -> SimOutcome {
        for _ in 0..max_ticks {
            // 1. Pre-tick fault injection (timer jitter, spurious IRQs).
            self.plan.inject(&mut self.rng, self.clock, self.irq, &mut self.trace);

            // 2. Advance the mock clock by 1 tick (or N if FaultPlan says so).
            let now_before = self.clock.now();
            self.clock.tick();

            // 3. Inject the canonical timer IRQ for this tick.
            self.irq.inject_timer();

            // 4. Drive the kernel's preempt_tick path (the seam consumer).
            //    This runs `irq.ack_timer(); for id in clock.drain_expired(now)
            //    { wake(id); } rotate_or_resched();` against the mocks.
            kernel::task::preempt_tick();

            // 5. Record the post-tick state delta.
            self.trace.push_post_tick(now_before, self.clock, self.irq);

            // 6. Check invariants. Bail with the trace + seed on first violation.
            if let Some(v) = self.cfg.invariants.check(self) {
                return SimOutcome::Violation { seed: self.cfg.seed, tick: self.clock.now(), violation: v, trace: self.trace.take() };
            }

            // 7. Termination?
            if self.cfg.until.is_satisfied(self) { break; }
        }
        SimOutcome::Completed { seed: self.cfg.seed, trace: self.trace.take() }
    }
}
```

**Why linear tick-by-tick, not event-driven**: tick-by-tick is what
the kernel scheduler already *is*. The PIT/LAPIC timer hands
`preempt_tick` a clock that has advanced by exactly one tick. An
event-driven simulator that skips empty ticks (the FoundationDB Flow
shape) introduces a model-the-model problem: the simulator's notion of
"empty" must agree with the kernel's, and any disagreement is a
silent determinism bug. Linear tick-by-tick costs ~1 µs per tick on
the host (measured against `MockClock` in the RFC-0005 unit tests);
at 100 Hz simulated this is 100 ns/s of simulated time wall-clock
overhead — well below the kernel-internal cost of `BTreeMap` drains
and ready-bank rotation. We can afford it.

If a specific test demands sub-tick fault injection (it doesn't, in
v1), the seam already supports it via `MockTimerIrq::inject_timer()`
returning to control between `pre_tick` and `post_tick` hooks. That
path is intentionally not exercised in v1 — it would be a v2
extension defended by an actual flake that demands it.

### State-machine model interface: `(Tick, Event)` trace stream

External observers see the simulator as a stream of records:

```rust
// simulator/src/trace.rs
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TraceRecord {
    pub tick: u64,                  // raw tick at which this record was emitted
    pub event: Event,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Event {
    // Driven by the simulator before stepping the kernel
    TimerInjected,
    SpuriousTimerInjected,            // FaultPlan-driven extra IRQ
    ClockAdvanced { from: u64, to: u64 },
    // Observed from the kernel after stepping
    TaskWoken      { id: TaskId, deadline: u64 },
    TaskReady      { id: TaskId, prio: u8 },
    TaskBlocked    { id: TaskId, on: BlockReason },
    Switch         { from: TaskId, to: TaskId },
    // Lifecycle (#501 surface)
    Fork           { parent: TaskId, child: TaskId },
    Exec           { id: TaskId, image: u64 /* hash */ },
    Exit           { id: TaskId, status: i32 },
    Wait           { parent: TaskId, child: TaskId },
    SignalDelivered{ from: TaskId, to: TaskId, sig: u8 },
    // Invariant violations the harness flags itself
    Violated       { invariant: &'static str, detail: String },
}
```

This is the *external* observable surface — what `proptest`,
`#390`'s stress runner, and a human reading `cargo run -p simulator
--bin replay -- --seed=…` all see. It is intentionally **not** a
snapshot/diff API: snapshots couple the trace shape to the kernel's
internal struct layout, breaking the trace any time a kernel struct
gains a field. An event stream over a stable enum is robust to
internal kernel evolution.

The trace is also `serde::Serialize`-able so a failing seed dumps a
JSON trace alongside the seed itself; reviewers can read the trace
without re-running anything.

### Reference state machine: invariants over the trace, not refinement (resolves Academic B2)

The Academic reviewer is correct: the v1 starter properties
("no task in `TaskReady` and `TaskBlocked` simultaneously"; "every
`Wait` is preceded by an `Exit` of the same child id") are TLA+-style
**safety invariants over the trace**, not refinement claims that
"every kernel transition is a transition the reference would have
made." The RFC makes this explicit:

> **Phase 2 v1 uses invariant-based property checking, not
> refinement-based.** The `(Tick, Event)` trace is a sequence; an
> invariant is a predicate `P(prefix) -> bool` that must hold over
> every prefix. Properties are written as:
>
> ```rust
> trait TraceInvariant {
>     fn check(&self, prefix: &[TraceRecord]) -> Result<(), Violation>;
> }
> ```
>
> The reference state machine (`SchedulerStateMachine`) is **not**
> consulted as an oracle. Its only role is to *generate sequences
> of transitions* (Spawn / Block / Wake / TickN / InjectIrq) that
> the simulator then drives the kernel through. The kernel's
> resulting trace is checked against the invariants directly, with
> no refinement comparison.

This avoids the false-positive cost of refinement (every
timing-permitted variation triggering a property failure) while
keeping the soundness guarantee that *invariant violations are real
bugs*. Liveness invariants (Academic-A1 absorbed) are expressed as
"no-progress timer" assertions in the same shape: `LivenessTimeout
{ task: TaskId, since_tick: u64, max: u64 }` flags any task that
remains `Blocked` for more than `max` simulated ticks. Default
`max = 1000`; tests that intentionally test long-blocking paths
override per-test. This is Lamport's safety-vs-liveness distinction
made operational, mirroring TigerBeetle's no-progress-timer
discipline.

A future Phase 3 RFC may add refinement checking (or symbolic
execution à la Hyperkernel — Academic-A3 absorbed: the seam shape
inherited from RFC 0005 doesn't preclude it) once the invariant set
matures and there's evidence false-positive cost is acceptable.

### RNG stream coupling: `proptest` master-seeds the simulator (resolves Academic B1)

The simulator has multiple named RNG streams (`fault_rng`,
`wakeup_order_rng`, `task_arrival_rng`) all derived from a single
**master seed** via `splitmix64`. The integration with `proptest`
is one-way:

> **`proptest`'s `TestRng` master-seeds the simulator's master
> seed.** The `SchedulerStateMachine: ReferenceStateMachine` impl
> reads `proptest`'s next u64 once, at `init_state`, and uses that
> value as `Simulator::with_seed(value)`. The simulator's internal
> RNG streams derive deterministically from there.

Consequences:

1. A `proptest` failure reports a single seed (proptest's). Replay
   with `cargo test -- --proptest-seed=<seed>` reproduces both the
   transition sequence *and* the simulator's internal fault plan.
2. `proptest`'s shrinker mutates the *transition sequence* (its
   own input space). Each shrunk sequence runs against a *fresh*
   simulator with the same proptest seed — so the simulator's
   master seed stays fixed across one shrink chain. The shrinker
   reduces the sequence; it doesn't reduce the fault plan.
3. To reduce the fault plan once the transition sequence is
   minimal, the §Seed minimization pass (Stage 2 — FaultPlan
   delta-debugging) runs **after** proptest has shrunk the
   sequence. This separates the two concerns and matches Hypothesis's
   internal-test-case-representation discipline (MacIver, 2019)
   adapted to the seam: proptest owns sequence-space minimization;
   the simulator owns fault-plan minimization.

This is the design choice the Academic reviewer asked the RFC to
commit to. It is not the only viable choice — a fully-Hypothesis-style
"single byte-stream representation" would let one shrinker minimize
both — but `proptest` doesn't expose that primitive today, and
re-implementing it for v1 is the kind of speculative engineering
that this RFC's discipline rejects.

Academic-A2 (`HashMap` ordering): a `clippy::disallowed_types` lint
forbids `std::collections::HashMap` in `simulator/` and any
`#[cfg(feature = "sched-mock")]`-gated kernel code, with an explicit
escape hatch for `HashMap<K, V, FxHasher>` where determinism is
preserved. Enforced in the same CI job that runs `cargo clippy`.
Adding to Roadmap item 1.

### Property-test integration: `proptest-state-machine`-compatible

`simulator/src/proptest_model.rs` exposes:

```rust
pub struct SchedulerStateMachine;
impl proptest_state_machine::ReferenceStateMachine for SchedulerStateMachine {
    type State      = ReferenceState;       // reference scheduler model
    type Transition = SchedulerTransition;  // Spawn / Block / Wake / TickN / InjectIrq / …
    fn init_state() -> BoxedStrategy<Self::State> { … }
    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> { … }
    fn apply(state: Self::State, transition: &Self::Transition) -> Self::State { … }
    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool { … }
}
```

This is the integration point #391 plugs into. The reference model
is intentionally tiny — the kernel itself is the system under test;
the reference is a 200-line scheduler that gets the *invariant
right* (no task runs while another holds its blocked bit; every wake
eventually leads to a switch; etc.) without trying to reimplement
priority bands. Most properties check shape, not exact equivalence.

The `(Tick, Event)` trace from the live kernel is compared against
the reference model's predicted transitions; mismatches are the
property failure. Shrinking falls out automatically from
`proptest-state-machine`.

### Failure-injection scope

**In Phase 2 v1:**

- **Timer drift** — the FaultPlan can advance the clock by 0, 1, or N
  ticks per simulator step (per-step distribution from the seeded
  RNG), modeling delayed timer IRQs.
- **Spurious timer IRQs** — `MockTimerIrq::inject_timer` is called
  more than once per simulated tick, modeling LAPIC/PIT lost-edge
  retries.
- **Wakeup re-ordering inside a tick** — when multiple tasks share a
  deadline, the order they appear in the drained `Vec<TaskId>` is
  permuted by the seeded RNG. This is the most direct lever on
  fork/exec/wait races (#501): "did the parent's `wait` see the
  child's `exit` first, or vice versa?" becomes a seed.

  **Note (OS-engineer A3 absorbed):** wakeup-reorder is strictly
  *more* nondeterminism than production exhibits — production
  `time::WAKEUPS` does not reorder. Reorder is a stress fault that
  finds bugs of the form "this code is wrong if drain order ever
  shuffles," not a faithful production reproduction. Failing
  seeds whose only trigger is reorder are still real bugs (the
  code shouldn't depend on `BTreeMap` insertion order), but they
  must be labeled as such in bug reports so reviewers don't
  dismiss them as "can't happen on real hardware." The trace's
  `feature_set` records which faults were active; the reproduction
  bug's title should include `[stress: wakeup-reorder]` when
  applicable.

  **Softirq-ordering note (OS-engineer A1 absorbed):** the kernel's
  softirq path runs between `ack_timer` and `rotate_or_resched`
  inside `preempt_tick`. The simulator's between-tick observation
  hook does not see intermediate softirq state — only the final
  state after `preempt_tick` returns. The reference state machine
  must therefore not predict transitions that softirqs cause; the
  v1 invariants are written to be robust to softirq-internal state.
  When a future flake requires softirq-ordering visibility, that's
  Phase 2.1 RFC #4 (post_ack_hook on `TimerIrq`, foreshadowed in
  RFC 0005 §"What is *not* covered by this seam").

**Explicitly deferred to Phase 2.1 follow-up RFCs:**

- **Hardware faults (`#PF`, `#GP`, `#DF`).** Requires a new seam in
  `kernel/src/arch/x86_64/idt.rs` that the simulator can drive — this
  RFC does not extend the seam. Without that surface, "inject a
  `#PF`" means "execute an invalid instruction in QEMU", which is
  not a host-side capability. Phase 2.1 RFC #1.
- **Syscall-entry interposition.** Currently syscalls land via the
  IDT and reach `kernel/src/syscall/mod.rs::syscall_entry` in ring
  3 → ring 0 transition; the host simulator has no ring 3. A faked
  syscall driver is feasible but is its own design (which calling
  convention does the simulator pretend to use? how does it resolve
  user pointers?). Phase 2.1 RFC #2.
- **IPI / SMP modeling.** The kernel is BSP-only today (RFC 0005
  §"Wait until SMP forces scheduler refactoring" — rejected,
  deferred). When SMP lands, the seam grows `cpu_id`-aware methods;
  Phase 2.1 RFC #3 extends the simulator to drive multi-CPU runs.
  Until then there is no IPI to inject.
- **MMIO / device fault injection.** virtio-blk, future virtio-net,
  PCI config-space corruption — each driver is its own seam. The
  filesystem track has a parallel "Vmm/Disk seam" RFC pending, and
  that's where torn-write injection belongs.

This Phase 2.1 boundary is **honest, not aspirational**. v1 ships the
fault scope the existing seam supports. Each Phase 2.1 RFC is an
independent unit of work; nothing in v1 should be designed
"speculatively" for those follow-ups (the seam discipline applies).

### Failing-seed-to-repro path (resolves UserSpace B1)

The seed is the API. Every layer of the harness commits to making
it findable from a CI failure:

1. **Simulator panic hook (Roadmap item 2 deliverable).** The
   `Simulator::with_seed` constructor installs a process-global
   panic hook (idempotent — last installer wins, with a warning) of
   the form:

   ```text
   thread 'sim_thread' panicked at … VIBIX_SIM_SEED=0xDEADBEEF
   COMMIT=abc123 TRACE=target/sim-traces/0xDEADBEEF.json
   ```

   The `VIBIX_SIM_SEED=` prefix is a load-bearing string —
   downstream tooling (CI annotations, `auto-engineer` agents) greps
   for it. The format is committed in `docs/design/simulator.md`
   and is part of the API contract.

2. **CI surfacing.** A GitHub Actions workflow step parses simulator
   output for the `VIBIX_SIM_SEED=` line and emits a structured
   GitHub Actions annotation
   (`::error file=…::Simulator failed at seed=… commit=…
   trace=…`). The trace JSON is uploaded as a GitHub Actions
   artifact `sim-trace-${seed}-${commit}.json` with 30-day
   retention (Testing-A1 absorbed).

3. **Local repro.** A developer copies the seed from the CI
   annotation and runs:

   ```sh
   cargo run -p simulator --bin replay -- --seed=0xDEADBEEF
   ```

   …which re-runs the simulator at the recorded commit, producing a
   byte-identical trace. To avoid re-running 100k ticks just to
   read the trace, an alternate form replays from a previously
   dumped trace:

   ```sh
   cargo run -p simulator --bin replay -- --trace-json=path/to.json --explain
   ```

   The `--explain` flag pretty-prints a tabular timeline (UserSpace-A3
   absorbed): `Tick 42: Fork(parent=1, child=2) Switch(1→2)`.

4. **Property-test failures.** When a `proptest` failure fires
   inside the simulator harness, the simulator's master seed is
   reported alongside `proptest`'s own minimization output. The
   integration is one-way: proptest's seed seeds the simulator's
   master via `splitmix64` (committed in §Reference state machine
   below), so a single proptest seed reproduces both the
   transition sequence *and* the simulator's fault plan. Reproduce
   with `cargo test -p simulator <test_name> --
   --seed=<proptest-seed>`.

5. **`#[non_exhaustive]` on `Event`** (UserSpace-A1 absorbed): the
   `Event` enum is `#[non_exhaustive]` so external consumers
   (`#391`, `#390`, future tooling) match exhaustively only inside
   the simulator crate; new variants don't break SemVer.

6. **Panic hook captures the seed even on `SIGINT`** (UserSpace-A4
   absorbed): the simulator installs a `Ctrl-C` handler that prints
   `VIBIX_SIM_SEED=…` before exiting, so an interrupted long-run
   test doesn't lose the seed.

### Seed minimization and trace shrinking (resolves Testing B2)

A 100k-tick failing trace is unreadable. The simulator commits to a
two-stage minimizer that runs automatically on any CI-failed seed
before the trace is checked in:

**Stage 1 — Tick-window binary search.** The minimizer re-runs the
seed under a `max_ticks` cap and binary-searches the smallest cap
that still violates the invariant. Cost: ~log₂(100k) ≈ 17 reruns,
typically completing in seconds because most reruns fail-fast at
the new cap.

**Stage 2 — FaultPlan delta-debugging.** The seeded RNG draws are
the input. The minimizer records the sequence of fault decisions
the seeded run produced (write-only buffer alongside the trace),
then replays with successively-disabled subsets:

- Disable wakeup-reorder fault → does it still fail? If yes, that
  fault wasn't load-bearing; drop it from the minimal seed.
- Disable spurious-IRQ fault → same question.
- Disable timer-jitter fault → same question.

The result is the minimum subset of fault classes the failure
needs, recorded in a `FaultProfile` checked-in alongside the seed.
A reader of the bug report sees: "fails with seed 0xDEADBEEF when
wakeup-reorder is enabled (the other faults are not needed)" —
which is enormously more debuggable than "fails at 100k ticks of
mixed faults."

CLI:

```sh
cargo run -p simulator --bin replay -- --seed=0xDEADBEEF --minimize
```

This is mandatory before checking in a repro seed (Roadmap item 6
gate); auto-minimization is non-negotiable for the harness's
debuggability promise. The shrinker is implemented by Roadmap
item 6.5 (new — added below).

### CI perf budget (resolves Testing B1)

The original budget arithmetic was wrong. The honest numbers:

| Workload | Per-PR fast suite | Nightly suite |
|---|---|---|
| Realistic per-tick cost (preempt_tick + drain + trace push) | 5–20 µs | same |
| Per-PR target | **100 seeds × 10k ticks ≈ 10–20 s** | n/a |
| Nightly target | n/a | **10k seeds × 100k ticks**, parallelized via rayon over seeds (16-core CI) **≈ 10–20 min** |
| Regression-detection seed list | **bounded by `tests/seeds/*.txt` (~50 seeds × 10k ticks ≈ 5–10 s)** | rolled into nightly |

The fast suite (per-PR) splits into:
- The bounded regression seed list (always run; <10s).
- A randomized exploration pass at 100 seeds × 10k ticks (10–20s).

Total per-PR overhead: ~20–30s. Trust-able. (Testing-A5 absorbed:
the regression-vs-exploration distinction is now explicit.)

The nightly suite uses `rayon` to parallelize across seeds (each
seed is a fully independent simulator run, embarrassingly parallel)
and runs `cargo nightly` only when `kernel/src/task/**` /
`kernel/src/sync/**` changed since the last successful nightly
(Testing-A2 absorbed).

Roadmap item 8 is rewritten to reflect these numbers.

### Reproducibility envelope

> **Identical seed + identical git commit + identical
> `rust-toolchain.toml` + identical `simulator` Cargo features →
> identical `(Tick, Event)` trace.**

That is the contract. Concretely:

1. **Seed**: a `u64` passed to `Simulator::with_seed`. ChaCha8 PRNG
   (deterministic, no OS entropy). Multiple named streams
   (`fault_rng`, `wakeup_order_rng`, `task_arrival_rng`) all derived
   from the master seed via `splitmix64` so adding a new fault knob
   doesn't shift the numbers an old seed produced. (TigerBeetle
   pattern.)
2. **Git commit**: trace records commit hash on dump. Replay refuses
   to run if the working tree is dirty (`git status --porcelain`
   non-empty) unless `--allow-dirty` is passed — borrowed from
   TigerBeetle.
3. **Rust toolchain**: today `rust-toolchain.toml` says `channel =
   "nightly"` with no date. **This RFC commits to pinning a specific
   nightly date** in the same PR that lands the simulator skeleton
   (Roadmap item 1). Without a date pin, a different nightly = a
   different libcore = potentially a different `BTreeMap` iteration
   order = a different trace from the same seed. This is the single
   most likely silent-determinism bug; pinning is cheap.
4. **Simulator features**: `Cargo.toml`'s `[features]` table records
   what's enabled. The trace dump includes the active feature set so
   replay can verify it.

**Out of scope for the envelope** (i.e., we explicitly *don't* commit
to determinism across these axes):

- Host CPU architecture / OS — host x86_64 Linux only is supported;
  macOS / aarch64 hosts may produce different traces and that's
  fine. CI runs on linux-x86_64.
- LLVM version — pinned transitively by the rust-toolchain pin; we
  don't pin it independently.
- `BTreeMap` iteration order across libcore versions — addressed by
  the toolchain pin above.
- The kernel's *production* timing — the simulator's tick is not
  10 ms wall-clock, it's a counter advance. PIT calibration is not
  exercised. (This is by design and matches RFC 0005's
  `CLOCK_REALTIME` exclusion.)

This envelope is roughly the same as VOPR's (`seed + git commit`)
plus an explicit toolchain pin. It is materially weaker than
Antithesis's hypervisor-level envelope and *intentionally so* — we
don't need ring-3 instruction-stream determinism, only kernel
scheduler-decision determinism.

### Key data structures

- `simulator::Simulator` — owns mock refs, RNG, trace, fault plan.
- `simulator::trace::TraceRecorder` — `Vec<TraceRecord>` with a
  `take()` on bail-out + a `push_*` per kernel-side observation.
- `simulator::FaultPlan` — pre-baked or RNG-driven schedule of
  jitter / spurious-IRQ / wakeup-permute decisions per tick. Pure
  function `(seed, tick) -> FaultDecision` so the same plan replays
  identically.
- `simulator::SchedulerStateMachine` — `proptest_state_machine`
  reference model for #391.

### Algorithms and protocols

The simulator is an outer event loop around the kernel's existing
`task::preempt_tick`. There is no new scheduling algorithm — we are
*observing* the scheduler, not replacing it. The fault plan's
algorithm is "draw from a seeded RNG and inject; record the
decision." The reference state machine is a 200-line scheduler used
only as a property-checking oracle. Determinism is preserved because
every nondeterminism source the kernel could see goes through
`Clock` / `TimerIrq`, both of which are now `MockClock` /
`MockTimerIrq`.

### Kernel–Userspace Interface

N/A — Phase 2 is host-only test infrastructure. No syscalls, no
`/proc`, no `/sys`. The only kernel-side change is exposing a few
introspection helpers behind `#[cfg(feature = "sched-mock")]` (e.g.
`task::scheduler::ready_count()`, `task::current_id_unchecked()`)
that the simulator reads. Those helpers are nm-check-guarded out of
release ELFs by the existing #669 mechanism — they ride the same
guard as `MockClock` itself.

### Reproduction commitments (P0 flakes the v1 simulator MUST
reproduce)

The following must each be reducible to a single failing seed in v1.
Roadmap item 6 explicitly gates on this:

- [x-target] **#501 — fork/exec/wait flakiness** — *committed*.
  Fork, exec, exit, wait, signal delivery are all in the v1 Event
  enum and exercised by the wakeup-permute fault. This is the
  primary justification for Phase 2 existing; if v1 cannot reproduce
  it, v1 is incomplete.
- [x-target] **#478 — userspace init never emits "init: hello from
  pid 1" after IRETQ** — *committed conditionally*. The flake is
  almost certainly a wakeup that never drains; that is observable as
  a trace where `init` appears in `TaskBlocked` and never in
  `TaskReady`. If the flake turns out to be a IRETQ-microcode race,
  it falls out of scope (host simulator has no IRETQ) — that finding
  itself is a useful Phase 2.1 surface request.
- **#527 — residual ring3 user-stack `#PF` at rip=0x4002c6** —
  *deferred to Phase 2.1*. The fault is a hardware `#PF`; without
  the IDT seam (Phase 2.1 RFC #1) the simulator can observe what
  the scheduler did *up to* the moment the `#PF` would fire, but
  cannot fire one. v1 narrows the trigger window by ruling out
  scheduler-level causes; pinning the rip itself waits for Phase 2.1.

This split is honest: the seam Phase 2 consumes is the
scheduler/IRQ seam. Hardware-fault flakes need a hardware-fault
seam, which is a separate RFC.

## Security Considerations

The simulator and its kernel introspection helpers live behind
`feature = "sched-mock"` and the host-only crate gate. Production
release ELFs (built by `cargo xtask build --release`) do not pull
the simulator crate or the `sched-mock` feature. No new
userspace-facing surface; no new MMIO; no new IDT entries. The
simulator is strictly a host-test artifact. A user who runs
`cargo test -p simulator` is running their own host process — the
trust boundary is host-process trust, not kernel-privilege trust.

### nm-check guard committed surface (resolves Security B1)

Phase 2 grows the surface of symbols the nm-check (#669) must
exclude from the release ELF, and commits to a concrete regex
**now** so the implementing PR cannot widen it silently. The
regex applies to the *demangled* form of every exported and
internal Rust symbol in the release ELF (`nm --demangle
target/release/kernel.elf`):

```text
^(.*::)?(Mock(Clock|TimerIrq|ClockState|IrqState)|sim_introspect_\w+|sched_mock_trace::push|SchedMockTrace\w*)$
```

Concretely the regex matches:

- `MockClock`, `MockTimerIrq`, and their internal state types
  (already gated by `feature = "sched-mock"` per RFC 0005).
- Any function whose name begins with `sim_introspect_` —
  the convention for new kernel-side test helpers (e.g.
  `sim_introspect_ready_count`,
  `sim_introspect_pending_blocked`).
- The `sched_mock_trace::push` trampoline that the
  `sched_mock_trace!` macro expands to (§Event emit points).
- Any future type prefixed `SchedMockTrace`.

Mangled-symbol robustness: Rust's `_R` v0 mangling encodes the
fully-qualified path, including `mock` / `sched_mock` module names,
in a recoverable form. The CI step demangles before grepping
(`nm --demangle=rust`), which on rust-1.84+ resolves both `_ZN…`
and `_R…` forms. New code that introduces a new prefix must update
this regex in the same PR, and the regex is cited at the top of
`kernel/src/task/env.rs` (and `kernel/src/sched_mock_trace.rs`)
with a comment so violations of the convention are visible at
review time.

This converts the "physically excluded from production" claim
back from an assertion into a verified invariant, restoring the
RFC-0005 §"Test-time wiring" property as Phase 2 grows the
mock surface.

### Trace attribution under dirty trees (resolves Security B2)

A trace dump records the commit hash *and* the tree-cleanliness
status. Concretely, every JSON dump contains:

```json
{
  "vibix_simulator_version": 1,
  "seed": "0xDEADBEEF",
  "commit": "abc123...",
  "tree_dirty": false,
  "rust_toolchain": "nightly-2026-04-27",
  "feature_set": ["sched-mock", "..."],
  "trace": [ /* events */ ]
}
```

`tree_dirty` is set to the result of `git status --porcelain`-non-empty
at the moment the trace was written. CI never produces dirty traces:
the PR's CI job runs in a clean checkout, and the simulator binary
**refuses to run** without `--allow-dirty` if `tree_dirty` would be
true. Locally, `--allow-dirty` is permitted but the trace's
`tree_dirty: true` is loud, and the replay binary refuses to verify
a trace whose `tree_dirty` is `true` against the recorded commit
(it explicitly says "this trace was produced from a dirty checkout
of `abc123`; the contents do not necessarily match commit
`abc123`"). Bug reports that cite a dirty trace are unambiguously
flagged as such; clean traces are unambiguously clean.

This resolves the attribution ambiguity: every trace is
self-describing about whether its commit hash actually corresponds
to the kernel under test. Borrowed from TigerBeetle's stricter
discipline (no `--allow-dirty` at all) but with a local-development
escape hatch that doesn't pretend the trace is canonical.

Security-A1 (resolved-feature-set in trace JSON) and Security-A2
(seed in panic + SIGINT output) are absorbed into §Failing-seed-to-repro
path above.

## Performance Considerations

The simulator is a host binary. It does not run in the kernel hot
path; it runs in `cargo test -p simulator`. Performance concerns are
*test throughput* (how many seeds per CI minute), not kernel
performance.

- Per-tick overhead: ~1 µs on the host (measured against `MockClock`
  in RFC-0005 unit tests). A 1 M-tick simulation is ~1 second
  wall-clock — well within a CI budget.
- RAM: the trace `Vec<TraceRecord>` grows linearly with simulated
  ticks. A 1 M-tick run with ~10 events/tick is ~80 MB at typical
  enum sizes. The simulator caps the trace at a configurable bound
  (`SimConfig::max_trace_records`, default 100k) and on overflow
  switches to "ring-buffer of last N records + total counter" — a
  failing seed gets re-run with the cap raised if the human needs
  the full history.
- CI cost: target is "1000 random seeds × 100k ticks each in under
  60s wall-clock for the per-PR fast suite." A nightly suite runs
  10× that. Numbers calibrated against shuttle's
  "most-bugs-in-hundreds-of-iterations" finding.

The kernel's *production* hot path is unchanged. `MockClock` does
not exist in the release binary.

## Alternatives Considered

### Separate-binary simulator with stable C ABI

Considered and rejected (§Crate boundary above). Wraps the
already-Rust-trait seam in a C ABI for no isolation gain;
introspection becomes serializable shapes that are a maintenance
tax. The single trade-off it would buy — running a frozen kernel
binary against a separate simulator — is not a capability we need.

### Event-driven simulation (skip empty ticks)

Considered and rejected for v1 (§Driver loop). Faster, but
introduces a model-the-model problem (simulator's "empty" must
agree with kernel's), which is exactly the silent-determinism class
of bug DST is supposed to eliminate. Linear tick-by-tick is fast
enough on the host and matches the kernel's own state-machine shape.
Re-examinable in a future RFC if measured throughput becomes a
blocker.

### Snapshot/diff state-machine API instead of `(Tick, Event)`
trace

Considered and rejected. Snapshot APIs couple the trace shape to
internal kernel struct layouts; every layout change is a trace
break. An enum-stream over stable variants is robust to internal
evolution.

### Extend the `Clock` / `TimerIrq` traits with new methods now

Rejected. RFC 0005 §"Discipline" forbids speculative methods. v1
flakes are reproducible without new trait methods. The first new
method that lands will be the one Phase 2.1's IDT-seam RFC
introduces, and that PR is where its semantics get debated.

### Build the simulator on top of loom or shuttle directly

Loom is the wrong scale (exhaustive C11 permutation; designed for
small primitives like `Arc`, not whole-scheduler exploration).
Shuttle is closer in spirit but assumes a hosted Rust runtime with
`std::thread`-shaped concurrency — the kernel is `no_std` and uses
its own scheduler. Neither tool's machinery applies directly. We
borrow shuttle's *iteration-budget heuristic* (hundreds, not
millions) and loom's *cfg-gated swap discipline* without reusing
their code.

### Wait until SMP lands and design the simulator with multi-CPU
from day one

Rejected, mirroring RFC 0005's symmetric rejection. The flakes that
justify Phase 2 are BSP-only flakes today (#501, #527, #478 all
manifest on a single CPU). Coupling Phase 2 to SMP delays the
observable benefit by months and creates a single high-risk PR that
introduces multi-core *and* the simulator simultaneously. Phase 2.1
RFC #3 extends the simulator to SMP when SMP itself lands.

### Use a generic state-machine model framework (e.g., stateright)

Considered. Stateright is a general model-checker; useful, but its
abstraction layer (state, action, init) is more general than what
we need and forces the kernel to be re-expressed *as* a stateright
model. proptest-state-machine is lighter, idiomatic to the wider
Rust ecosystem (#391's chosen tool already), and the
`ReferenceStateMachine` trait is easy to implement against the
simulator's `(Tick, Event)` trace. Stateright remains a reasonable
target for a future *formal-verification* RFC, separate from this
randomized harness.

## Open Questions

All open questions are deferred to implementation per the resolutions
recorded below. None block RFC acceptance.

Post-defense advisory items absorbed (defense cycle 1):

- *VIBIX_SIM_SEED= panic-hook string is a stable interface* (Sec-A1
  re-review) — call out explicitly in the implementation that this
  string is greppable forever; document in §"Reproducibility envelope"
  and `docs/design/simulator.md`.
- *`preempt_tick` re-entrancy guard should be active under all
  `sched-mock` builds, not just `cfg(debug_assertions)`* (OS-A1
  re-review) — implementation uses `cfg(any(debug_assertions, all(test,
  feature = "sched-mock")))` (or simpler: always-on when `sched-mock`).
- *`--explain` agent-stable output format* (UserSpace-A1 re-review) —
  ship `--explain=table|json|tsv` with `tsv` as the agent-stable form.
- *Custom `Ord` impls in `simulator/` and sched-mock-gated kernel code
  must be reviewed for determinism* (Academic-A1 re-review) — add to
  the `docs/design/simulator.md` checklist.
- *Nightly suite path filter should include `simulator/**`*
  (Testing-A1 re-review) — extend the filter in Roadmap item 9.

These are implementation conveniences, not design changes; they ride
the relevant Roadmap items.

- **Pinning a specific nightly date.** The Reproducibility Envelope
  requires it. *Lean: pin in Roadmap item 1 to whatever nightly is
  current the day that PR opens; bump by an explicit followup PR
  every ~6–8 weeks driven by the regular toolchain-update cadence,
  with a saved-trace replay as part of that PR's gate.*
- **Trace serialization format.** JSON is human-readable but
  verbose; bincode/postcard is compact but opaque. *Lean: JSON for
  v1 (debugging is the bottleneck, not bytes-on-disk); revisit if a
  100k-record trace becomes a CI-storage problem.*
- **Whether `task::scheduler::introspect()` helpers should be a
  fixed surface or grow per-test.** *Lean: grow per-test under
  `sched-mock`; nm-check guards them out of release; if the surface
  exceeds ~20 helpers we revisit with a "scheduler test API" RFC.*
- **Reference state machine completeness.** How much of the
  scheduler's behavior the reference model encodes is a
  precision/recall trade-off (more model = more bugs found, more
  false-positives from model-vs-real disagreement). *Lean: start
  minimal — just the FIFO ready-bank invariants and the
  exit-before-reap invariant — and grow per-flake.*
- **#478's IRETQ-vs-wakeup classification.** v1 commits to
  reproducing #478 *if* it's a wakeup-drain bug. If it's an IRETQ
  microcode race, that finding is itself useful (it requalifies the
  flake as Phase 2.1 surface). *Resolved by running the v1
  simulator against #478 and observing the trace.*
- **CI budget calibration.** Is 1000 seeds × 100k ticks the right
  per-PR cost? *Lean: ship with that default; promote to nightly-only
  if PR latency becomes a complaint; re-tighten when seeds catch a
  real bug to demonstrate ROI.*
- **Phase 2.1 RFC dependency ordering.** The three follow-ups
  (IDT seam, syscall-entry seam, SMP simulator) are independent in
  principle. *Lean: file all three as issues at Phase 2 merge,
  prioritize whichever the next observed flake demands first.*

## Implementation Roadmap

Independently-landable, dependency-ordered. Each item is reviewable
on its own and CI-green at every step. Items 1–2 land
infrastructure that the rest depend on; items 3–5 build the trace
and fault machinery; items 6–8 land the actual P0-flake repros and
properties; items 9–11 are documentation and follow-up.

- [ ] **(1) Host-target buildability of `kernel/` + Rust nightly
      pin + lints.** Audit `kernel/src/{task,sync,signal,syscall}/`
      for `target_os = "none"` gates that block host build under
      `feature = "sched-mock"`. Add a parallel
      `#[cfg(all(not(target_os = "none"), feature = "sched-mock"))]`
      arm to each — primarily in `kernel/src/task/env.rs` (host
      `env()` reading from `thread_local! SIM_ENV`) and
      `kernel/src/sync/` (host `IrqLock` = `spin::Mutex`). Pin
      `rust-toolchain.toml`'s `channel` to a dated nightly (e.g.
      `nightly-2026-04-27`). Add `clippy::disallowed_types` lint
      forbidding `HashMap` under `sched-mock`. New CI job:
      `cargo build -p kernel --target x86_64-unknown-linux-gnu
      --features sched-mock` runs alongside the bare-metal build
      and the nm-check.
- [ ] **(2) Add `simulator/` crate skeleton + panic hook + replay
      binary stub.** New workspace member, depends on `kernel` with
      `features = ["sched-mock"]`, host-target only. Installs the
      `VIBIX_SIM_SEED=…`-prefixed panic hook on construction.
      `cargo run -p simulator --bin replay -- --seed=… [--explain]
      [--minimize] [--allow-dirty]` argument shape committed (no
      bodies yet). CI: `cargo test -p simulator` runs (empty).
- [ ] **(3) Implement `Simulator` + linear tick-by-tick run loop.**
      Wires `MockClock` + `MockTimerIrq` via `install_sim_env`,
      drives `kernel::task::preempt_tick()` per tick, exposes
      `Simulator::with_seed(u64).run(max_ticks: u64) -> SimOutcome`.
      Includes the `cfg(debug_assertions)` re-entrancy guard inside
      `preempt_tick`. CI: integration test spawning 3 dummy tasks,
      running 1000 ticks, asserting each gets at least one switch.
- [ ] **(4) Add `(Tick, Event)` trace recorder + JSON dump (with
      tree_dirty + commit + toolchain + feature_set fields).**
      `TraceRecorder` with `#[non_exhaustive] enum Event`;
      `serde::Serialize`; replay binary now reads/writes JSON and
      `--explain` pretty-prints. CI: golden-file test on a
      hand-crafted seed; refuses to run on dirty tree without
      `--allow-dirty`.
- [ ] **(5) Wire kernel-side introspection + `sched_mock_trace!`
      macro.** Add `kernel/src/sched_mock_trace.rs` with the
      compile-out-when-off macro; place emit-point calls at
      `fork`, `exec`, `exit`, `wait`, signal-deliver paths.
      `task::scheduler::sim_introspect_*` helpers added behind
      `sched-mock`. Extend nm-check regex to the committed surface
      from §nm-check guard committed surface. CI: assembly
      inspection step verifies `fork` syscall emits zero code under
      release build.
- [ ] **(6) Add `FaultPlan` (timer jitter, spurious IRQs, wakeup
      reorder).** RNG via `rand_chacha::ChaCha8Rng`; named streams
      via `splitmix64`. Each fault independently togglable.
      Per-tick fault decisions logged into a `FaultDecisionsLog`
      written alongside the trace.
- [ ] **(6.5) Implement seed minimizer (Stage 1 + Stage 2).**
      `--minimize` flag drives tick-window binary search and
      FaultPlan delta-debugging; emits the minimal `FaultProfile`.
      Mandatory before any seed is checked in as a repro. CI:
      smoke test that synthetic-violation seed minimizes from
      100k ticks down to <100 ticks.
- [ ] **(7) Reproduce #501 (fork/exec/wait flakiness) as a single
      minimized failing seed.** Gate on Phase 2 v1 "done": PR
      includes a checked-in seed + minimized JSON trace + a
      `tests/repro_501.rs` reading the seed, running the simulator,
      and asserting the violation is observed at the recorded tick.
      Closes #501 when the underlying bug is then fixed.
- [ ] **(8) Add invariant + liveness checkers + proptest-state-machine
      integration.** `simulator/src/invariants.rs` with the v1
      starter properties (no task in Ready+Blocked simultaneously;
      every Wait preceded by an Exit; `LivenessTimeout` for
      blocked > 1000 ticks). `simulator/src/proptest_model.rs`
      exposes `SchedulerStateMachine: ReferenceStateMachine`,
      master-seeding the `Simulator` from `proptest`'s `TestRng`.
      This is #391's integration point.
- [ ] **(9) CI: per-PR fast suite + nightly suite + artifact
      upload.** Per-PR: bounded regression seeds in `tests/seeds/`
      (~50 × 10k ticks ≈ 5–10s) plus randomized exploration (100
      × 10k ticks ≈ 10–20s). Nightly: 10k × 100k ticks via
      rayon-over-seeds (≈10–20 min on 16-core CI), gated to fire
      only when `kernel/src/{task,sync}/**` changed since last
      successful nightly. Failing seed traces upload as
      `sim-trace-${seed}-${commit}.json` with 30-day retention; PR
      job emits structured GitHub Actions annotations parsed from
      the `VIBIX_SIM_SEED=…` panic-hook output.
- [ ] **(10) Reproduce #478 if classifiable.** Run v1 simulator
      against #478 surface. If a wakeup-drain trace shows up, check
      in seed. If IRETQ microcode race, file Phase 2.1 RFC #2
      (syscall-entry seam) with the finding written up.
- [ ] **(11) File Phase 2.1 follow-up RFC discussions.** Four
      discussions: IDT/hardware-fault seam (for #527), syscall-entry
      seam (for IRETQ-class flakes), SMP simulator (extends to
      `cpu_id`-aware seam), softirq `post_ack_hook` (foreshadowed
      in RFC 0005). Each is its own RFC, prioritized when the next
      flake demands it.
- [x] **(12) Document the simulator in `docs/design/simulator.md`.**
      One-page quick reference parallel to
      `docs/design/scheduler-seam.md`: how to write a new repro,
      how to read a trace, how to add a new event variant, how to
      add a new fault knob, the host-substitute table for
      sync primitives, the reproducibility-envelope contract
      verbatim, and the panic-hook `VIBIX_SIM_SEED=` format
      string as a stable interface. Landed via issue #726.

## Cross-references

- [`docs/design/simulator.md`](../design/simulator.md) — as-shipped quick reference (writing a scenario, the trace JSON schema, FaultPlan vocabulary, seed/RNG-stream rules, the `replay` / `minimize` CLI, the determinism envelope, host-substitute table). Read this first when actually working with the simulator; this RFC carries the design rationale, the as-shipped doc carries the API surface.
- [RFC 0005 — Scheduler / IRQ Seam](0005-scheduler-irq-seam.md) — the trait surface this simulator consumes.
- [`docs/design/scheduler-seam.md`](../design/scheduler-seam.md) — as-shipped companion to RFC 0005.
- [`simulator/docs/trace-schema.md`](../../simulator/docs/trace-schema.md) — authoritative `schema_version = 1` JSON contract.
