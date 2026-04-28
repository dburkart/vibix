# Scheduler / IRQ Seam — Design Note

**Status as of 2026-04-27:** Phase 1 partially landed. Trait surface is in
tree (PR #672 / issue #665); production adapters, the `env()` accessor,
caller migration, and mock impls are tracked but unmerged
(issues #666, #667, #668, #669, #670).

**Source of truth for rationale:** [RFC 0005](../RFC/0005-scheduler-irq-seam.md).
This note is the one-page quick reference downstream RFCs (SMP, Phase-2
simulator) can cite without re-reading the full RFC. Where RFC 0005 and
this note disagree, this note describes what *shipped*; the RFC describes
what was *proposed*. Any drift is a bug — file an issue.

---

## What the seam is

Two traits in `kernel/src/task/env.rs` that the scheduler core will call
through (once caller migration lands) instead of reaching directly into
`crate::time::*` and `crate::arch::*`:

- `Clock` — monotonic time + one-shot future-tick wakeups.
- `IrqSource` — preemption-relevant IRQ acknowledgement.

Production wires both to the existing PIT/LAPIC/`time::WAKEUPS`
machinery via zero-sized adapters. Tests and the future host-side
simulator (Phase 2, out of scope) wire them to mocks or seeded impls.

Phase 1 is a refactor only. End state: identical kernel behavior, plus
two trait definitions, one accessor, and a single production wire-up
site.

## File layout

| Path | Status | Contents |
|---|---|---|
| `kernel/src/task/env.rs` | landed (#672) | `Tick`, `Clock`, `IrqSource`, `TaskId` |
| `kernel/src/task/mod.rs` | landed (#672, `pub mod env;` only) | will host `HwClock`, `HwIrq`, `env()` (#666) |
| `kernel/src/time.rs` | unchanged today | will drop to `pub(crate)` after caller migration (#667) |

## Trait surface (as merged)

```rust
pub type TaskId = usize;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Tick(pub(crate) u64);

impl Tick {
    pub fn checked_add(self, ticks: u64) -> Option<Self>;
    pub fn saturating_add(self, ticks: u64) -> Self;
    pub fn raw(self) -> u64;
}

pub trait Clock: Sync {
    fn now(&self) -> Tick;
    fn drain_expired(&self, now: Tick) -> alloc::vec::Vec<TaskId>;
    fn enqueue_wakeup(&self, deadline: Tick, id: TaskId);
}

pub trait IrqSource: Sync {
    fn ack_timer(&self);
}
```

That is the entire Phase-1 surface: two traits, four methods. Method
signatures match `kernel/src/task/env.rs` verbatim as of commit
`a0c25d7`.

Note that `TaskId` is a `pub type` alias (not the `pub use` re-export
the RFC sketched). The behavioral contract is identical; the alias was
chosen so a future generation-counted id refactor can change the
underlying type in one place without breaking impls.

## Contracts (binding on impls)

### IRQ-context safety

All `Clock` and `IrqSource` methods MUST be safe to call from both task
context and interrupt context. Implementors that hold internal state
across methods MUST mask IRQs while held (the existing `time::WAKEUPS`
already uses `crate::sync::IrqLock`). A non-IRQ-safe impl is a soundness
bug — the timer ISR will deadlock the first time it fires while a
syscall holds the impl's internal lock.

### Init order

`Clock` impls MUST be safe to call any time after the global allocator
is up — earlier than `task::init()`. Boot-phase callers (TSC
calibration, early `serial_println` timestamps) reach the clock before
the scheduler exists. The production `HwClock` (#666) is zero-sized and
trivially satisfies this; non-ZST impls (mocks, simulator) must either
initialize lazily on first call or document their requirement and have
the boot sequence install them before that point.

### Tick unit invariant

`Tick` units must be uniform across all `Clock` impls within a single
boot. Today every impl uses PIT ticks (10 ms). When the LAPIC-timer
migration lands every impl in that build switches together — there is
no mixed-unit world. Violating this breaks Liskov substitution and is a
correctness bug, not a performance one.

### `env()` accessor (not yet landed — issue #666)

`task::env()` returns `(&'static dyn Clock, &'static dyn IrqSource)`.
The production accessor body MUST contain no `Once`, no `Mutex`, no
atomic load other than the `&'static` reference materialization — see
the equivalence property below for why. Test/sim builds may swap the
accessor to a thread-local `OnceCell` of boxed impls.

## Equivalence property and verification

The production wire-up is observationally equivalent to the pre-RFC
direct calls iff:

1. **Pure forwarding.** Every `HwClock` / `HwIrq` method body is a
   single call into the existing global, no added state, no
   transformation other than `Tick` ↔ `u64` boxing, no early return.
2. **No added synchronization.** `env()` returns `&'static` references
   to two ZST statics — no lock, no `Once::call_once`, no atomic load.
3. **Identical IRQ-context safety.** `HwClock` cannot weaken the
   contract because it owns no additional state.

The PR that lands caller migration (#667) MUST gate on a **byte-identical
QEMU serial-log diff** before vs. after the `preempt_tick` / `sleep_ms`
migration, captured by the existing scheduler integration suite. This
is the equivalence test the RFC committed to; it is borrowed in spirit
from Linux's `clocksource_verify_percpu` discipline (compare two impls
under load) and adapted to compare the new code path against the old.

## What is *not* covered by this seam

Explicitly out of scope for Phase 1, by RFC §"Alternatives Considered":

- Per-CPU state, `cpu_id()`, per-CPU timer ack — deferred to the SMP
  RFC. The seam shape does not preclude per-CPU evolution; `env()` can
  become `env(cpu_id)` additively without churning method signatures.
- IDT install, IOAPIC redirection programming, IPI send — Phase 2 or
  SMP, when a second impl actually needs them.
- Softirq dispatch (`kernel/src/task/softirq.rs`) runs in IRQ-tail
  context after `ack_timer` but before `rotate_or_resched`, and stays
  *direct* (not through the trait). Phase 2 may need a `post_ack_hook`
  to model softirq ordering deterministically; that is exactly the
  kind of speculative method the discipline below forbids adding now.
- `Console`, `Vmm`, `Allocator` seams — each is a separate harness and
  belongs to its own RFC.
- `CLOCK_REALTIME` and wall-clock time (CMOS, NTP) — do not cross the
  scheduler boundary; userspace gets a non-deterministic realtime clock
  under simulation by design. Only `CLOCK_MONOTONIC`-class time funnels
  through `Clock`.

## The discipline

> **A `Clock` or `IrqSource` trait method is added only when a second
> implementation actually needs it.**

Speculative methods ("we'll probably want this when…") are rejected.
The first new method that appears is the one the host-side simulator
(Phase 2) needs first, and that PR is where its semantics get debated.
This rule is stated positively so future PRs can be pushed back on with
a citation. It mirrors loom's discipline (don't gate types you don't
actually need to swap) and TigerBeetle's (the simulator surface is the
*minimum* required to mock I/O).

POSIX-time syscalls — `nanosleep`, `clock_nanosleep`, `pselect` /
`ppoll` / `epoll_wait` timeouts, `futex` with timeout, `sigtimedwait`,
`clock_gettime(CLOCK_MONOTONIC)` — MUST route through `Clock`, not
through a side-channel into `time::*`. This is the commitment that
makes "deterministic scheduler ⇒ deterministic userspace timing"
actually true under simulation; it will be verified per-syscall as
each one lands.

## Phase-2 LTS-equivalence flag

The Phase-2 simulator RFC will need the scheduler's
externally-observable behavior to be expressible as a labeled
transition system over `(Clock-event, IrqSource-event) → state
transition`. The seam shape here is *necessary* for this but may not
be *sufficient* — softirq ordering (above) is the known suspect. The
Phase-2 RFC must validate sufficiency before relying on the v1 trait
surface; this note flags it so the validation is not forgotten.

## Cross-references

- [RFC 0005 — Scheduler / IRQ Seam](../RFC/0005-scheduler-irq-seam.md)
- [`docs/tasks.md`](../tasks.md) — task subsystem overview
- [`docs/time.md`](../time.md) — PIT-driven monotonic clock
- Issues: #665 (traits, merged), #666, #667, #668, #669, #670 (open)
