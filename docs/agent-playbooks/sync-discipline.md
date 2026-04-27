# Sync discipline (vibix kernel)

This appendix collects the synchronisation rules the kernel relies on
across modules. Each rule is mechanically enforced where possible
(debug assertions, `#[deny]` lints, lock-acquire instrumentation) and
documented here for the cases code review still has to catch.

## Lock ordering

The canonical order is documented in each module's header. The
**must-not-invert** rules live here so any reviewer can grep one file:

- `process::TABLE` → `task::SCHED` is **forbidden**. Always sample
  `task::current_id()` *before* taking `TABLE`. The session/pgrp
  syscalls (`sys_getsid`, `sys_getpgid`) follow this rule; older code
  that took `TABLE` first and called `current_id()` from inside the
  critical section was the documented #478 lock-ordering hazard.
- `process::TABLE` → `tty.ctrl` is allowed and used by
  `process::try_acquire_ctty_atomic`. The reverse order is forbidden.
- `process::TABLE` → `WaitQueue::wait_while` is forbidden. `wait4`
  uses an exit-event counter snapshot to avoid holding `TABLE` across
  the predicate.

## IF discipline (#478, #647)

The plain `spin::Mutex` types in the kernel (e.g. `process::TABLE`)
are **not** IRQ-masking. They must be acquired with `RFLAGS.IF=1` so
the timer ISR can preempt a stuck holder.

- `process::current_pid()` debug-asserts `IF=1` on entry and uses an
  instrumented `try_lock` loop that panics if the spin exceeds
  `CURRENT_PID_SOAK_THRESHOLD`. Rationale: the failure trace in #478
  showed CPU stuck in a `current_pid` `pause`-spin loop while the
  timer ISR fired only 24 times across a 120 s window — classic
  starvation by an interrupt-disabled holder.
- Callers in interrupt-disabled regions (top-half ISRs, ISR-deferred
  tasklets, anything inside an `IrqLock` guard) must cache the pid
  value before disabling IRQs. Calling `current_pid()` from such a
  region trips the debug-assert immediately.
- `IrqLock` is the right primitive for data shared between task and
  ISR context. Plain `spin::Mutex` is the right primitive for
  task-context-only data, but only when callers can guarantee the
  lock is never held across a scheduling point or with IF cleared.

## Soak detection

`CURRENT_PID_SOAK_THRESHOLD` is sized so ordinary contention never
trips it (~1e8 iterations ≈ tens of ms on real hardware, multiple
seconds on un-accelerated QEMU) but a wedged holder is caught loudly
within the smoke-test timeout. The release build skips the check
because the soak path is debug-only — tripping it is a *bug
detection*, not a runtime guard.

## Smoke-side detection

`xtask smoke` asserts the presence of two new markers:

- `irq-pre-ring3: ticks=N` — emitted in `jump_to_ring3` immediately
  before the IRETQ to ring-3.
- `irq-post-ring3: ticks=… delta=…` — emitted on the very first
  SYSCALL from ring-3.

If userspace never observably runs (the #478 signature) the second
marker simply never appears and smoke fails on the missing marker.
The delta value is informative for triage but is not gated, because
the gap between IRETQ and the first SYSCALL is normally well below
one 10 ms tick on real hardware.
