---
rfc: 0005
title: Scheduler / IRQ Seam for Deterministic Simulation Testing
status: Draft
created: 2026-04-27
---

# RFC 0005: Scheduler / IRQ Seam for Deterministic Simulation Testing

## Abstract

Extract the scheduler core in `kernel/src/task/` from its direct dependence on
the PIT timer counter, the LAPIC, and the global tick wakeup table by routing
those calls through two minimal injected dependencies: a `Clock` trait
(monotonic time + future-tick scheduling) and an `IrqSource` trait (interrupt
acknowledgement + drain). Production builds wire these to the existing
PIT/HPET/APIC drivers with zero observable behavior change; tests can supply
mocks; a future host-side simulator (out of scope here) can supply seeded
implementations to turn today's flaky concurrency bugs into reproducible
seeds. This RFC covers Phase 1 only — the seam, not the simulator.

## Motivation

Two concrete pains motivate the seam now:

- The long-running fork/exec/wait quality sprint (#501) and the residual
  ring-3 user-stack `#PF` flake (#527) are both *intermittent* — the current
  toolchain can only retry-and-hope. Every retry burns ~6–8 hours of CI
  wallclock under `-Zbuild-std` + QEMU. Without a deterministic harness, a
  flake reproduced once may not reproduce again, and root-causing happens by
  staring at logs. A seeded simulator turns each flake into a `cargo test
  -- --seed=0xDEADBEEF` — but only if the scheduler can be driven without
  real hardware.
- The SMP track (#30, #88–#91) will refactor the scheduler regardless. Doing
  the testability seam *first* gives us a deterministic regression harness
  before SMP starts churning the same code, rather than landing two
  destabilizing rewrites back-to-back.

The proposal here is a *refactor*, not a new feature. The end state for
Phase 1 is identical kernel behavior, the same passing test suite, plus two
new trait definitions and a single production wire-up site.

## Background

Today the scheduler is in `kernel/src/task/` (`mod.rs`, `scheduler.rs`,
`switch.rs`, `task.rs`, `softirq.rs`, `priority.rs`). The PIT ISR calls
`preempt_tick()` in `task::mod`, which:

1. Reads `crate::time::ticks()` (a global `AtomicU64` advanced by the PIT
   IRQ handler) to compute deadlines.
2. Drains `crate::time::drain_expired(ticks())`, a global `BTreeMap<u64,
   Vec<TaskId>>` of pending wakeups guarded by an `IrqLock`.
3. Acks the IRQ via the architecture-specific path (PIC/LAPIC EOI in
   `kernel/src/arch/x86_64/{pic,apic}.rs`).
4. Hands control to the priority-aware ready bank
   (`task/scheduler.rs::Scheduler::pop_highest`).

Time and IRQ are reached through *crate-global* statics today —
`time::TICKS`, `time::WAKEUPS`, the LAPIC MMIO `Once<LocalApic>` —
which means there is no in-process way for a test to advance time
without going through real hardware.

### Prior art surveyed

| Source | Lesson taken |
|---|---|
| TigerBeetle VOPR | Three traits — `Time`, `Network`, `Storage` — keep production and simulator on identical code paths. Discipline: *no globals* for these capabilities. |
| FoundationDB simulator (Flow) | Determinism only works if *every* nondeterminism source goes through the runtime. The cost of one escape hatch is the entire harness. |
| Linux clocksource / clockevents | Mature precedent for splitting "read time" (clocksource) from "set next event" (clockevent_device). Rating-based runtime selection across TSC/HPET/LAPIC validates that the seam shape proposed here is well-trodden. |
| Tokio `loom` | cfg-gated type-aliasing in a project-local `sync` module is the lowest-friction Rust pattern; loom replaces `Mutex`, `Atomic*`, `thread::spawn`, `UnsafeCell`. Production code is unchanged. |
| commonware-runtime (Rust) | Trait surface = `Clock` + `Spawner` + `Network` + `Storage` — confirms "minimum 2–3 traits" is sufficient for an async runtime DST harness. |
| S2.dev / Tokio test clock | Time advances on `sleep()` calls; clocks include a "schedule event for the future" method, not just `now()`. Validates `Clock::schedule_tick(deadline)` belongs in the trait. |
| Polar Signals (state-machine DST) | A maximalist "everything is a state machine" approach has high cognitive overhead and slows engineers. Argues for *not* abstracting more than the harness needs. |
| Hermit (Microsoft Research) | Time, RNG, scheduling, and syscalls are the four nondeterminism sources. Phase 1 covers time + scheduling; RNG and syscall-replay are deferred. |

## Design

### Overview

Two traits, defined in a new file `kernel/src/task/env.rs`. The scheduler
core takes them by `&dyn` reference at the call boundary; production wires
them to existing drivers via a single `static` per trait.

```rust
// kernel/src/task/env.rs

/// Monotonic tick count since boot. Opaque newtype so we can swap the
/// underlying width or units without ABI churn.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Tick(pub u64);

/// Source of monotonic time and one-shot future tick wakeups for the
/// scheduler. The scheduler never reads a clock register or arms a timer
/// directly — it goes through this trait.
pub trait Clock: Sync {
    /// Current monotonic tick count.
    fn now(&self) -> Tick;

    /// Drain all wakeup ids whose deadline is `<= now`. The implementor
    /// owns the deadline structure (today: `time::WAKEUPS`); the
    /// scheduler only consumes the drained ids.
    fn drain_expired(&self, now: Tick) -> alloc::vec::Vec<usize>;

    /// Enqueue task `id` for a wakeup at `deadline`. Idempotent on
    /// `(deadline, id)` pairs.
    fn enqueue_wakeup(&self, deadline: Tick, id: usize);
}

/// Source of preemption interrupts for the scheduler. Only the
/// per-tick-hot-path operations live here; one-shot IDT install,
/// IOAPIC redirection, and IPI send are *not* part of this trait
/// (see Alternatives Considered).
pub trait IrqSource: Sync {
    /// Acknowledge the timer IRQ that drove the current `preempt_tick`
    /// call. Today: LAPIC EOI write; on legacy PIC: PIC EOI.
    fn ack_timer(&self);
}
```

That is the entire surface for Phase 1. Two traits, four methods.

### Production wire-up

In `kernel/src/task/mod.rs`:

```rust
// Production-only: zero-sized adapters over the existing globals.
struct HwClock;
impl Clock for HwClock {
    fn now(&self) -> Tick { Tick(crate::time::ticks()) }
    fn drain_expired(&self, now: Tick) -> Vec<usize> {
        crate::time::drain_expired(now.0)
    }
    fn enqueue_wakeup(&self, deadline: Tick, id: usize) {
        crate::time::enqueue_wakeup(deadline.0, id)
    }
}

struct HwIrq;
impl IrqSource for HwIrq {
    fn ack_timer(&self) { crate::arch::ack_timer_irq(); }
}

static HW_CLOCK: HwClock = HwClock;
static HW_IRQ: HwIrq = HwIrq;

/// Returns the production environment. Tests in `cfg(not(target_os =
/// "none"))` builds and the future simulator override this.
pub fn env() -> (&'static dyn Clock, &'static dyn IrqSource) {
    (&HW_CLOCK, &HW_IRQ)
}
```

`preempt_tick()` becomes:

```rust
pub fn preempt_tick() {
    let (clock, irq) = env();
    irq.ack_timer();
    let now = clock.now();
    for id in clock.drain_expired(now) {
        wake(id);
    }
    // existing rotation logic, unchanged
    rotate_or_resched();
}
```

`task::sleep_ms()` becomes:

```rust
pub fn sleep_ms(ms: u64) {
    let (clock, _) = env();
    let ticks_to_wait = ms.div_ceil(crate::time::TICK_MS).max(1);
    let deadline = Tick(clock.now().0.saturating_add(ticks_to_wait));
    let id = current_id();
    clock.enqueue_wakeup(deadline, id);
    block_current();
}
```

The `time` and `apic` modules keep their internals — the seam is at the
*scheduler's* edge, not at the driver's edge. `time::WAKEUPS` and
`time::TICKS` continue to exist; the scheduler simply no longer reads them
directly.

### Generics vs trait objects

Trait objects (`&'static dyn Clock`) for v1, deliberately:

- The vtable load is one cache-resident indirect call per `preempt_tick`
  (100 Hz today, ≤ 1 kHz under any plausible LAPIC-timer migration). Cost
  is in the noise next to the cache misses of a context switch.
- Generics (`Sched<C: Clock, I: IrqSource>`) would propagate the type
  parameters through every function that touches the scheduler, including
  syscall entry. That is precisely the kind of refactor we want to avoid
  during a phase-1 testability change.
- If profiling later shows the indirection matters (it won't), the trait
  objects can be promoted to generics in one PR — the call sites already
  go through a single `env()` accessor.

This matches loom's discipline (cfg-gated swap, no generics) and the
pattern used by Linux's `clockevents_device` (struct of function pointers
≈ vtable).

### Test-time wiring

In host (`cfg(not(target_os = "none"))`) and kernel-test
(`cfg(test_harness)`) builds, `env()` resolves to a thread-local
`OnceCell<(Box<dyn Clock>, Box<dyn IrqSource>)>` that tests install
manually. A `MockClock` implementation (in `kernel/src/task/env.rs`
behind `#[cfg(any(test, not(target_os = "none")))]`) advances on explicit
`tick()` calls; `MockIrqSource::ack_timer` is a no-op. This alone improves
in-kernel integration test isolation (today, several tests poke
`time::TICKS` directly).

### Key data structures

No new persistent state. `HwClock` and `HwIrq` are zero-sized; the existing
`time::WAKEUPS`, `time::TICKS`, and LAPIC `Once` retain ownership of all
state. The opaque `Tick(u64)` newtype replaces bare `u64` deadlines at the
scheduler boundary so a future `Clock` impl could carry richer time
(e.g. simulated nanoseconds) without API churn.

### Algorithms and protocols

Unchanged. `preempt_tick` still drains expired wakeups and calls the
existing `rotate_or_resched` logic in the priority-aware ready bank
(`task/scheduler.rs`). The only delta is the call boundary: scheduler
calls `clock.now()` instead of `time::ticks()`, etc.

### Kernel–Userspace Interface

N/A — kernel-internal refactor only. No syscall, `/proc`, or `/sys`
changes.

### Migration plan inside Phase 1

The roadmap below breaks the seam into four landable PRs so the tree never
goes red for more than one merge:

1. **Add `task::env` module + traits, no call-site changes.** Compiles
   into the kernel, dead code. Reviewed in isolation — no behavior risk.
2. **Wire `HwClock`/`HwIrq` adapters and the `env()` accessor.** Adapter
   methods just call into the existing globals.
3. **Migrate `preempt_tick`, `sleep_ms`, and the wakeup paths to go
   through `env()`.** This is the substantive change; CI gate on existing
   in-kernel scheduler tests + the fork/exec/wait smoke.
4. **Migrate any remaining `time::ticks()` / `time::drain_expired()` /
   `time::enqueue_wakeup()` callers in `task/`** so the only caller of
   those `time::*` functions is `HwClock`. Then `pub` → `pub(crate)` on
   them as a hygiene gate that prevents regressions.

## Security Considerations

Trait dispatch through `&'static dyn` does not change the privilege model:
the production `env()` returns references to two `static` items, both
zero-sized adapters over the same globals the scheduler already uses. No
new memory is exposed to userspace; no new MMIO; no new IDT entries.

The one concern worth naming: a `Clock` trait that `Sync`s a `Vec<usize>`
wakeup list out of `drain_expired` *appears* to expose task ids, but those
ids are scheduler-internal and never crossed into userspace. The trait is
strictly kernel-internal.

The mock/simulator implementations live behind `cfg(any(test_harness, not(target_os
= "none")))` and are physically excluded from production binaries —
verified by the existing `cargo xtask build --release` produced by CI.

## Performance Considerations

Hot path: `preempt_tick` runs at 100 Hz today (PIT) and is bounded above
by the eventual LAPIC-timer migration to ≲ 1 kHz. The added cost per tick
is one indirect call (vtable load) plus one accessor function call to
`env()`. On the 100 Hz hot path that is well under 1 µs of CPU time per
second; on a 1 kHz hot path it is still < 0.01 % overhead, which we will
not be able to measure above noise floor of the existing
`scheduler_smoke` benchmark.

`task::sleep_ms` is not a hot path — it's a yielding syscall. The same
indirect call there is irrelevant.

Memory overhead: `HwClock` and `HwIrq` are ZSTs. The `Tick(u64)` newtype
is a no-cost wrapper. Net memory delta: zero.

Lock contention: unchanged. `time::WAKEUPS` is still the same `IrqLock<BTreeMap>`;
the scheduler simply reaches it through `HwClock::drain_expired` /
`HwClock::enqueue_wakeup` instead of directly.

SMP scalability: the trait objects are per-process `static`s today and
will have to be re-thought for per-CPU state when SMP lands (see
"Does this constrain SMP?" in Open Questions, and the explicit
`cpu_id` discussion in Alternatives Considered). The seam shape proposed
here does *not* preclude per-CPU evolution — `env()` can become
`env(cpu_id)` without churning the trait methods themselves.

## Alternatives Considered

### Wider trait surface (per-CPU state, IDT install, IPI send)

Rejected for v1. The discussion-author's lean was correct: the IDT is
installed exactly once at boot, and IPI send appears in code paths
(SMP shootdown, eventual `wake_cpu`) that don't yet exist. Abstracting
them now is speculative — we'd be designing for a harness we have not
built. When SMP lands and forces real per-CPU state, the trait surface
extends additively (`fn cpu_id(&self) -> u8`, possibly a separate
`PerCpu` trait) without breaking the v1 callers. Polar Signals' DST
post is a cautionary tale here: a maximalist state-machine refactor
slowed their team meaningfully and constrained future design.

### Generics instead of `&dyn`

Rejected for v1 (see Generics vs trait objects above). Promotable later
in one PR if profiling demands it; the `env()` accessor is the only
chokepoint.

### Wait until SMP forces scheduler refactoring

Rejected. The strategic motivation here is *converting flakes into
seeds* — that benefit accrues to #501 / #527 and similar bugs *now*,
months before SMP lands. Coupling the seam to SMP delays that benefit
and creates a single high-risk PR that simultaneously changes the
scheduler shape *and* introduces multi-core. Land the testability seam
first, against today's stable BSP-only scheduler, so the SMP work has a
deterministic regression harness from day one. This RFC is explicit
about not designing for SMP-specific concerns it would be premature to
resolve.

### Cfg-based type-aliasing seam (loom-style)

Considered seriously — loom's pattern of swapping `Mutex` via
`#[cfg(loom)]` is elegant for *primitives*. It does not fit here
because the scheduler interacts with time and IRQs via *behavior*
(drain expired wakeups, ack the timer), not via *types*. Trait objects
naturally express behavior; type aliasing would need wrapper types
that re-implement those behaviors anyway. We borrow the *discipline*
from loom (production code unchanged; test/sim code wires the
alternative implementation) without copying the cfg mechanism.

### Abstract `Console`, `Vmm`, `Allocator` in the same change

Rejected, as the discussion proposed. Each is a separate seam for a
separate harness. `Vmm` in particular wants its own RFC because
crash-consistency simulation will dictate the trait shape. Doing them
in one PR would be a 3000-line refactor that is impossible to review
incrementally and impossible to bisect when (not if) it regresses.

## Open Questions

These are explicitly flagged for resolution during implementation, not
before merge:

- **`Clock` resolution after LAPIC-timer migration.** Today `Tick` is PIT
  ticks (10 ms). When the kernel migrates to LAPIC-timer (likely as part
  of SMP), `Tick` becomes finer-grained. Does the trait grow `now_ns()`,
  or does `Tick` change units silently? *Lean: add `now_ns()` as a default
  method that delegates to `now()`, then override per-impl when finer
  granularity is available. Decided in the PR that lands the LAPIC-timer
  migration.*
- **Per-CPU `Clock` for TSC-drift modeling.** Almost certainly needed
  when SMP lands. The seam shape here does not constrain it: `env()` can
  become `env(cpu_id)` and `Clock` can grow a `cpu_id()` accessor
  additively. *Resolved in the SMP RFC; not blocking here.*
- **Timer-IRQ ack on AP cores.** When APs come up they each need their own
  LAPIC EOI path. `IrqSource::ack_timer` will become per-CPU (same
  evolution as `Clock`). *Same answer: resolved in the SMP RFC; not
  blocking here.*
- **Should `Clock` own `WAKEUPS` outright?** Today `HwClock::drain_expired`
  is a thin shim over `time::WAKEUPS`. There's an argument for moving
  `WAKEUPS` into the `Clock` impl so the scheduler's wakeup machinery is
  fully encapsulated by the trait. Defer until we have a second `Clock`
  impl (mock or simulator) and can see whether code naturally collects
  there.
- **Trait-object lifetime if we ever want `Box<dyn Clock>`.** v1 uses
  `&'static dyn Clock` so the question doesn't arise. If host-side tests
  want to swap clocks per-test they'll need `OnceCell<Box<dyn Clock>>` —
  manageable but worth documenting before the first test does it.

## Implementation Roadmap

Independently-landable, dependency-ordered. Each item is reviewable on
its own and CI-green at every step.

- [ ] Add `kernel/src/task/env.rs` with `Tick`, `Clock`, `IrqSource` trait
      definitions and doc comments. No call-site changes; module is dead
      code at this point.
- [ ] Add `HwClock`, `HwIrq` zero-sized production adapters + `env()`
      accessor in `kernel/src/task/mod.rs`. Still no callers.
- [ ] Migrate `preempt_tick` and the IRQ-ack path in `kernel/src/task/`
      to call through `env()`. Existing scheduler tests + fork/exec/wait
      smoke must stay green.
- [ ] Migrate `task::sleep_ms` and any other `time::enqueue_wakeup` /
      `time::drain_expired` callers in `task/` to go through `env()`.
- [ ] Tighten `time::ticks` / `time::drain_expired` /
      `time::enqueue_wakeup` to `pub(crate)` (or stricter) so the only
      caller is `HwClock`. Acts as a regression gate.
- [ ] Add a `MockClock` + `MockIrqSource` in
      `kernel/src/task/env.rs` behind `#[cfg(any(test, not(target_os =
      "none")))]` and convert one existing in-kernel scheduler integration
      test to use them as proof-of-life.
- [ ] Document the seam in `docs/design/scheduler-seam.md` (one-page;
      links here) so the SMP RFC and the future Phase-2 simulator RFC can
      cite a stable target.
