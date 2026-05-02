# Host-Side DST Simulator — Design Note

**Status as of 2026-05-02:** Phase 2 v1 landed. Roadmap items 1–6.5
plus 8 from [RFC 0006](../RFC/0006-host-dst-simulator.md) are merged
on `main`; items 7 / 9 / 10 / 11 (P0-flake repros, CI sweep wiring,
follow-up RFCs) are tracked separately.

**Source of truth for rationale:** [RFC 0006](../RFC/0006-host-dst-simulator.md).
This note is the one-page quick reference downstream RFCs and
contributors can cite without re-reading the full RFC. Where RFC 0006
and this note disagree, this note describes what *shipped*; the RFC
describes what was *proposed*. Any drift is a bug — file an issue.

This is the Phase 2 companion to
[`docs/design/scheduler-seam.md`](scheduler-seam.md): the seam doc
covers the trait surface; this doc covers the host driver that
consumes it.

---

## What the simulator is

A host-only Rust crate (`simulator/`) that drives the kernel's
`MockClock` + `MockTimerIrq` pair one tick at a time under a seeded
PRNG, recording every observable transition into a `(Tick, Event)`
trace. The crate is gated `cfg(not(target_os = "none"))`; the
bare-metal kernel ELF cannot pull it in.

Load-bearing claim: **identical seed + commit + pinned toolchain →
byte-identical trace**. Every public API is an artefact of
preserving that.

## Reproducibility envelope

The contract holds across exactly four axes: **seed** (`u64`
passed to `Simulator::new`), **git commit**, **toolchain**
(`rust-toolchain.toml` pins a dated nightly — `BTreeMap` iteration
order can shift between nightlies), and **feature set**
(`sched-mock` must be enabled; `clippy::disallowed_types` denies
`HashMap` / `HashSet` inside `simulator/`).

Out of scope: host CPU/OS, LLVM version (pinned transitively),
`CLOCK_REALTIME` semantics, ring-3 instruction streams.

## Writing a scenario

The minimal scenario:

```rust
use simulator::{Simulator, SimulatorConfig};

#[test]
fn my_scenario() {
    // install_sim_env panics on second call per thread.
    std::thread::spawn(|| {
        let mut sim = Simulator::new(0xDEAD_BEEF, SimulatorConfig::with_seed(0xDEAD_BEEF));
        sim.run_for(1_000);
        sim.check_liveness().unwrap();
    }).join().unwrap();
}
```

Determinism-preserving shape rules:

- **One `Simulator` per OS thread.** `Simulator::new` calls
  `task::env::install_sim_env`, which panics on a second install on
  the same thread. Tests that swap seeds spawn a thread per case.
- **Use `run_for(n)` or `run_until(predicate)`** — not a hand-rolled
  `for _ in 0..n { sim.step() }`. The helpers handle the
  predicate-check / clock-advance off-by-one and respect
  `cfg.max_ticks` (default 1 M).
- **Don't construct `MockClock` / `MockTimerIrq` directly.** The
  simulator owns leak-`'static` refs; reaching past `sim.clock()` /
  `sim.irq()` would race the per-thread `env()` slot.
- **`BTreeMap` / `BTreeSet`, never `HashMap` / `HashSet`.** The
  workspace lint forbids the latter inside `simulator/`. Custom
  `Ord` impls under `sched-mock` must be reviewed for determinism
  (no wall-time observation, no `addr_of` hashing, no
  `RandomState`).

Fault injection rides on top: build a `FaultPlan` and assign it to
`cfg.fault_plan`.

## The trace JSON schema

Authoritative spec: [`simulator/docs/trace-schema.md`](../../simulator/docs/trace-schema.md)
(`schema_version = 1`). Summary:

Every trace is `{ "schema_version": 1, "records": [ … ] }`. Each
record is `{ "tick": u64, "event": { "type": "<tag>", … } }`. Field
ordering inside every object is fixed; the round-trip property
`record → JSON → parse → byte-identical JSON` holds.

Variants emitted by `Simulator::step` today:
`tick_advance { from, to }`, `timer_injected`, `timer_irq_acked`,
`wakeup_fired { id }` (one per drained deadline, in seam order or
rotated by an active `wakeup_reorder` fault),
`fault_injected { kind }` (emitted *before* the corresponding
mock-mutation so a reader can attribute the next `timer_injected` /
`tick_advance` to the fault).

Schema-defined but **not yet emitted by the live run loop** —
reserved for #718's kernel-side `sched_mock_trace!` macro:
`wakeup_enqueued`, `task_scheduled`, `task_blocked`, `syscall`,
`fault`. Invariant predicates over them already exist in
`simulator::invariants` and pass vacuously against today's traces.

`Trace::with_capacity_limit(N)` evicts oldest-first past `N` records
with a one-shot stderr warning. The default constructor is
unbounded — opt in deliberately.

## FaultPlan vocabulary

`FaultPlan` (`simulator::fault_plan`) is an ordered
`Vec<(tick, FaultEvent)>` consumed during `Simulator::step`. Three
variants ship in v1:

| Variant | Effect | Maps to |
|---|---|---|
| `SpuriousTimerIrq` | Extra `MockTimerIrq::inject_timer()` at `tick`. | LAPIC/PIT lost-edge retries. |
| `TimerDrift { ticks }` | Advance `MockClock` by `ticks` extra. | Delayed / coalesced timer IRQs. |
| `WakeupReorder { within_tick }` | Rotate next drained wakeup batch by `within_tick % batch.len()`. | Fork/exec/wait race surface (#501). |

JSON: `fault_plan_schema_version = 1`, byte-stable round-trip via
`FaultPlan::to_json` / `from_json`.

**Hardware faults are deferred.** `FaultEvent` does not carry
`InjectPageFault` / `InjectGeneralProtection` / `InjectDoubleFault`
— `compile_fail` doctests in `fault_plan.rs` pin this at the type
level. Adding one is a Phase 2.1 RFC reopening.

**Wakeup-reorder is super-deterministic.** Production
`time::WAKEUPS` does not reorder; a seed whose only trigger is
`WakeupReorder` is a "code that depends on `BTreeMap` insertion
order" bug, not a real-hardware bug. Bug reports tag such seeds
`[stress: wakeup-reorder]` so reviewers classify them correctly.

## Seed / RNG-stream rules

`SimRng::new(seed)` is the master; sub-streams come from
`SimRng::rng_for(name)`:

```rust
let mut faults_rng = sim.rng().rng_for("faults"); // ChaCha8Rng
```

The mix is FNV-1a(name) XOR master → splitmix64 splatter across the
32-byte ChaCha8 seed. ChaCha8 over ChaCha20 because 8 rounds are
statistically uniform on every 64-bit output and ~3× faster on long
sweeps.

**Adding a new sub-stream cannot perturb existing ones** — the
property that makes seed minimisation correct under code drift.

## CLI surface — `replay` and `minimize`

The simulator ships one binary, `replay` (in `simulator/src/bin/replay.rs`).
It has two argument shapes.

### Top-level form (replay a seed)

```sh
cargo run -p simulator --bin replay -- --seed 0xDEAD_BEEF [--trace-out path.json]
```

Accepts decimal, `0x`-prefixed hex, and underscore-separated forms
(`0xDEAD_BEEF`, `1_234_567`). Currently a stub: parses the
arguments, prints `replay: unimplemented (seed=…, trace_out=…)`,
exits `0`. The full run-loop body is queued behind issue #716; the
argument shape is committed *now* because RFC 0006 §"Local repro"
makes it a stable interface (CI annotations and auto-engineer
tooling grep for it).

### `minimize` subcommand

```sh
cargo run -p simulator --bin replay -- minimize \
    --seed 0xDEAD_BEEF --plan repro.json --out minimized.json [--max-ticks N]
```

Reads a `FaultPlan` JSON, drives the two-stage minimizer
(`simulator::minimize`), and writes a JSON document carrying the
shrunken plan plus the half-open `[lo, hi)` tick window. The
"reproduces" predicate is *the simulator panics* — every Phase 2
invariant violation surfaces as a `panic!` carrying
`SIMULATOR PANIC seed=… tick=…`.

| Stage | Effect | Bound |
|---|---|---|
| 1 — tick-window bisect | Smallest `[lo, hi)` that still panics. | `O(log T_max)` reproductions. |
| 2 — `ddmin` over `FaultPlan` | 1-minimal entry list. | `O(\|plan\|^2)` reproductions. |

Exit codes: `0` success, `1` runtime failure (input did not
reproduce, IO error, parse error), `2` CLI usage error. These are
load-bearing for shell tooling and must not drift.

## Host substitutes for kernel primitives

The simulator drives `Clock::drain_expired` / `TimerIrq::ack_timer`
through the trait objects from `task::env()`, which on host under
`sched-mock` is a per-thread `OnceCell<(&Clock, &TimerIrq)>`. It
does **not** call `kernel::task::preempt_tick()` — that function is
`cfg(target_os = "none")` and depends on FPU save/restore, `swapgs`,
and a hand-written context switch with no host equivalent.

| Kernel primitive | Host substitute |
|---|---|
| `task::env::env()` | `thread_local! SIM_ENV` (per-thread, so `cargo test` workers don't serialise) |
| `IrqLock<T>` | `spin::Mutex<T>` (preserves lock-order, not IRQ-mask semantics) |
| `cli` / `sti` / `iretq` | unreachable on host |
| `arch::ack_timer_irq` | `MockTimerIrq::ack_timer` (reached only via `env()`) |
| `task::preempt_tick` | not called — simulator exercises the seam contract; `sched-mock`-gated in-kernel tests cover the rotation path |

If a future flake's trigger lives below the seam
(microarchitectural ordering, `iretq` stack-fault, IPI race), it
routes to a Phase 2.1 RFC, not a v1 simulator extension.

## Failure surface — finding the seed in a CI log

Every panic inside the simulator goes through the panic hook
installed by `Simulator::new`. Before the standard panic message
and backtrace, it prints:

```text
SIMULATOR PANIC seed=<u64-decimal> tick=<u64-decimal>
```

This string is a stable interface — CI annotations, `auto-engineer`
tooling, and human grep workflows depend on its exact form.

> **Drift from RFC 0006.** RFC 0006 §"Failing-seed-to-repro path"
> originally specified `VIBIX_SIM_SEED=<hex>`. The as-shipped form
> is `SIMULATOR PANIC seed=<decimal>`. The shipped form is the
> contract; the RFC line is documentation drift.

## Worked example — capture, replay, minimize

```rust
use simulator::{FaultEvent, FaultPlan, Simulator, SimulatorConfig};

let mut cfg = SimulatorConfig::with_seed(0xDEAD_BEEF);
cfg.fault_plan = FaultPlan::from_entries([
    (50, FaultEvent::WakeupReorder { within_tick: 1 }),
]);
let mut sim = Simulator::new(0xDEAD_BEEF, cfg);
sim.run_for(10_000); // panics: `SIMULATOR PANIC seed=… tick=…`
let trace_json = sim.trace().to_json_string(); // for inspection
```

CI log surfaces the seed; replay locally:

```sh
cargo run -p simulator --bin replay -- --seed 0xDEAD_BEEF
```

After capturing the `FaultPlan` at failure time
(`FaultPlan::to_json` against the recorded plan), minimize:

```sh
cargo run -p simulator --bin replay -- minimize \
    --seed 0xDEAD_BEEF --plan repro.json --out minimized.json
```

The output is a 1-minimal `FaultPlan` plus the smallest `[lo, hi)`
tick window that still reproduces — typically <100 ticks with one
or two `FaultEvent` entries.

## Cross-references

- [RFC 0006 — Host-Side DST Simulator](../RFC/0006-host-dst-simulator.md) — the design rationale, prior art, and the full Phase 2 / 2.1 boundary.
- [`docs/design/scheduler-seam.md`](scheduler-seam.md) — the trait surface this simulator consumes (RFC 0005).
- [`simulator/docs/trace-schema.md`](../../simulator/docs/trace-schema.md) — authoritative `schema_version = 1` JSON contract.
- Source: `simulator/src/{lib.rs, trace.rs, fault_plan.rs, invariants.rs, minimize.rs}` and `simulator/src/bin/replay.rs`.
- Issues: #715 (skeleton), #716 (run loop), #717 (trace), #718 (kernel emit points, open), #719 (FaultPlan), #720 (minimizer), #722 (invariants), and the Phase 2.1 follow-ups (#728/#729/#730/#731).
