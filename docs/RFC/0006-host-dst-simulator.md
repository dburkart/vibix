---
rfc: 0006
title: Host-Side Deterministic Simulator (DST Phase 2)
status: Draft
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
the simulator crate or the `sched-mock` feature. The nm-check guard
landed in #669 statically verifies `MockClock` / `MockTimerIrq` /
new `task::scheduler::ready_count`-shaped helpers do not appear in
the release binary. This is the same guard RFC 0005 committed to;
Phase 2 extends the regex it greps for and runs in the same CI step.

No new userspace-facing surface; no new MMIO; no new IDT entries.
The simulator is strictly a host-test artifact. A user who runs
`cargo test -p simulator` is running their own host process — the
trust boundary is host-process trust, not kernel-privilege trust.

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
on its own and CI-green at every step.

- [ ] **Add `simulator/` crate skeleton + pin Rust nightly toolchain
      date.** New workspace member, depends on `kernel` with
      `features = ["sched-mock"]`, host-target only
      (`required-features` or `cfg(not(target_os = "none"))`). The
      same PR pins `rust-toolchain.toml`'s `channel` to a dated
      nightly (e.g. `nightly-2026-04-27`). Adds `cargo xtask sim
      --help` shim. CI: `cargo test -p simulator` runs in a new job;
      no test bodies yet.
- [ ] **Implement `Simulator` + linear tick-by-tick run loop.** Wires
      `MockClock` + `MockTimerIrq` into `task::env()` for the host
      build, drives `kernel::task::preempt_tick()` per tick, exposes
      `Simulator::with_seed(u64).run(max_ticks: u64)`. No fault plan
      yet (always `tick(); inject_timer();`). CI: an integration
      test that spawns 3 dummy tasks, runs 1000 ticks, asserts each
      gets at least one switch.
- [ ] **Add `(Tick, Event)` trace recorder + JSON dump.** `TraceRecorder`
      with the Event enum from §State-machine model interface;
      `serde::Serialize`; `cargo run -p simulator --bin replay --
      --seed=…` reads/writes JSON. CI: golden-file test on a
      hand-crafted seed.
- [ ] **Add `FaultPlan`: timer jitter, spurious IRQs, wakeup
      reorder.** RNG via `rand_chacha::ChaCha8Rng`, named streams via
      `splitmix64`. Each fault is independently feature-gateable so
      tests can isolate (e.g. `fault_plan.with_wakeup_reorder()`).
- [ ] **Wire kernel-side introspection helpers behind `sched-mock`.**
      `task::scheduler::ready_count()`,
      `task::scheduler::pending_blocked()`, plus enough to build the
      Event variants in this RFC's enum. nm-check guard (#669)
      regex extended to include `(Mock|sim_introspect_)`.
- [ ] **Reproduce #501 (fork/exec/wait flakiness) as a single
      failing seed.** This is the gate on Phase 2 v1 being "done".
      The PR includes a checked-in seed + JSON trace + a
      `tests/repro_501.rs` that reads the seed, runs the simulator,
      and asserts the violation is observed at the recorded tick.
      Closes #501 when the underlying bug is then fixed.
- [ ] **Add proptest-state-machine reference model.**
      `simulator/src/proptest_model.rs` exposes
      `SchedulerStateMachine: ReferenceStateMachine`. Two starter
      properties: "no task is in `TaskReady` and `TaskBlocked`
      simultaneously"; "every `Wait` is preceded by an `Exit` of the
      same child id". This is the integration point #391 plugs
      into.
- [ ] **CI: per-PR fast suite (1k seeds × 100k ticks) + nightly
      slow suite (10× that).** `cargo test -p simulator
      --test stress`. Target: <60s per-PR overhead.
- [ ] **Reproduce #478 if classifiable.** Run the v1 simulator
      against the #478 surface; if a wakeup-drain trace shows up,
      check in the seed. If it's an IRETQ microcode race, file
      Phase 2.1 RFC #2 (syscall-entry seam) instead with the
      finding written up.
- [ ] **File Phase 2.1 follow-up RFC issues.** Three discussions:
      IDT/hardware-fault seam (for #527), syscall-entry seam,
      SMP simulator. Each is its own RFC, prioritized when the next
      flake demands it.
- [ ] **Document the simulator in `docs/design/simulator.md`.**
      One-page quick reference (parallel to
      `docs/design/scheduler-seam.md`): how to write a new repro,
      how to read a trace, how to add a new event variant, how to
      add a new fault knob. Includes the reproducibility-envelope
      contract verbatim.
