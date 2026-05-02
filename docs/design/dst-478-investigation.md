# DST Phase 2 (#724): #478 Reproduction Attempt — Phase 2.1 Hand-off

**Status as of 2026-05-02:** Phase 2 v1 surface (timer faults, IRQ
reordering — `FaultEvent::SpuriousTimerIrq`, `FaultEvent::TimerDrift`,
`FaultEvent::WakeupReorder`) **cannot** reproduce
[#478](https://github.com/dburkart/vibix/issues/478) ("userspace init
never emits 'init: hello from pid 1' after IRETQ"). This document
records the attempt, classifies the failure mode, and points at the
Phase 2.1 surface that is required.

This is the alternate deliverable for [#724](https://github.com/dburkart/vibix/issues/724);
RFC 0006 §"Concrete flaky targets" committed to #478 *conditionally*
on the failure being scheduler-driven rather than hardware-fault-driven.

## Summary

[#478](https://github.com/dburkart/vibix/issues/478)'s production
evidence is unambiguous about the failure shape: the kernel emits
`init: iretq to ring-3` to the serial port, then **no userspace output
ever appears**. In particular, the `userspace/init/src/main.rs::_start`
diagnostic markers `init: pre-write marker` (a `write(2, …)` immediately
on entry, before any other userspace work) never appear in failing
runs. That makes the failure window strictly the gap between IRETQ
execution and the first userspace `syscall` instruction: ≤ a handful
of ring-3 instructions. The failure surface is therefore one of:

1. **IRETQ silently faulted on the first ring-3 instruction** (page-fault
   at the entry point, #GP from a malformed `iret` frame, microcode
   weirdness).
2. **The first userspace `syscall` trapped with the syscall handler
   silently swallowed** (bad `STAR`/`LSTAR`/`SFMASK`, mis-armed
   TSS.rsp[0] for the trampoline, segment-selector bug, etc.).
3. **The ring-3 stack/argv/auxv setup left a corrupted layout** that
   makes the first `syscall` immediately trap.

None of these are observable through the v1 simulator surface, which
models the kernel only at the `MockClock` / `MockTimerIrq` seam.

## What was tried

The `init_emit_after_iretq` scenario was prototyped against the v1
simulator:

| Tick | Modeled event |
|------|--------------|
| 0    | Boot (kernel up to scheduler online) |
| 2    | `INIT` task scheduled — model of `init: ring-3 entry task spawned` |
| 4    | `INIT` wakeup at deadline=4 — model of `init: iretq to ring-3` |
| 6    | `INIT` wakeup at deadline=6 — model of "first userspace `syscall` would have fired" |

A custom `SafetyInvariant` was added: **"INIT must have a
`Event::WakeupFired` record before tick 6 (T_FIRST_SYSCALL)"**. The
seed sweep (`1..10_000`, `density = 0.30`,
`VariantMask::all()` — i.e. timer faults + IRQ reordering) was run
against the scenario.

## Why no surfaced "violation" was a true reproduction

Empirically the sweep flagged ~700 seeds as violating the invariant
under high fault density. Inspection of the failing traces shows
every one of those is an artifact of `FaultEvent::TimerDrift` jumping
the clock past `T_FIRST_SYSCALL` *within a single step*: the post-drift
`TickAdvance` record carries `tick > 6` but the same step's later
`WakeupFired` records (which would clear the invariant for that tick)
have not yet been emitted at the moment the per-record predicate
runs. Even with the invariant rewritten to evaluate *only at end-of-step*
the surfaced failures all collapse to "drift carried the clock past
the model deadline before the drain emitted the matching wake" —
which is a tautology of the `TimerDrift` knob, not an analogue of
#478's failure.

Crucially, **the failure mode the simulator can model is "INIT wakes
late or out of order"**. #478's evidence (the `init: iretq to ring-3`
marker fires; the *very next* `init: pre-write marker` does not)
does not match any "wakes late" shape: the failure is in the ring-3
instruction stream, not in the scheduler's wakeup ordering. A
"wakes late" failure would surface at the next preempt-tick boundary,
not as silence after IRETQ, because the kernel-side scheduler already
scheduled `init` before the IRETQ marker was emitted.

The conclusion the RFC anticipated holds: **#478 is hardware-fault
territory, not scheduler-driven.**

## Required Phase 2.1 surface

The smallest seam that would let a host simulator reproduce #478 is a
**ring-3 trap-frame seam**: a host-buildable hook that lets the
simulator construct a synthetic `iretq` frame, drop into a
host-callable analogue of "execute the first ring-3 instruction," and
observe whether a synthetic page-fault or general-protection fault
fires before the first syscall.

Two adjacent surfaces have been considered:

1. **Page-fault injection seam** (RFC 0006 §"Failure-injection scope"
   open question). Lets the simulator inject a synthetic `#PF` at a
   chosen ring-3 RIP; combined with the IDT seam from Phase 2.1 RFC #1
   the simulator can model "the first ring-3 instruction page-faulted
   and the handler silently looped/double-faulted." This is the
   **most likely** surface for #478 if the failure is hypothesis (1)
   from the Summary above.
2. **Syscall-entry seam** ([#790](https://github.com/dburkart/vibix/issues/790),
   Phase 2.1 RFC #2). Adds a host-callable `dispatch_syscall(nr,
   args)` plus a user-pointer adapter trait so the host simulator can
   exercise the real `sys_*` handlers without the bare-metal preamble.
   Models hypothesis (2) — silent SYSCALL-trampoline mis-arming would
   show up as the dispatch shim returning `-EFAULT` or hanging on the
   first `write(2, PRE_WRITE_MSG)`.
3. **Ring-3 trap-frame seam** (not yet RFC'd). The most direct lever:
   a host-callable analogue of `jump_to_ring3` (`kernel/src/arch/x86_64/syscall.rs`)
   that exposes the constructed iret frame for invariant inspection.
   Models hypothesis (3) — corrupted argv/auxv/stack layouts
   surface as a malformed iret frame the invariant can flag.

Of the three, **the ring-3 trap-frame seam is the highest-leverage
surface for #478 specifically**, because the failing window is *entirely
within* the iretq → first-instruction → first-syscall transition. The
page-fault and syscall-entry seams add value on adjacent flakes (#527
and the fork/exec/wait families respectively).

## Recommendation

1. **Close [#724](https://github.com/dburkart/vibix/issues/724)** with a
   pointer to this document — the v1 surface attempt is complete and
   the result is a Phase 2.1 hand-off, which RFC 0006 §"Concrete flaky
   targets" calls out as a valid outcome.
2. **File a new Phase 2.1 RFC issue** for the ring-3 trap-frame seam,
   priority `P1`, `area:testing` + `track:userspace`. Cross-link to
   #478 and this document. The RFC should cover, at minimum:
   - A host-callable `simulator::ring3_iretq(frame: Iret64Frame) ->
     Ring3Trace` shim that does *not* execute ring-3 instructions but
     does record the iret frame, the simulator's reconstructed CR3 /
     `STAR` / `LSTAR` / `SFMASK` / TSS.rsp[0] / `SYSCALL_KERNEL_RSP`
     state, and emits `Event::Iret { frame, msrs }` into the trace.
   - An `Iret64FrameValid` safety invariant that asserts CS/SS
     selectors are ring-3 with appropriate RPL, RFLAGS has IF=1 +
     no reserved bits set, RIP is in the loaded ELF's executable
     segments, RSP is in a ring-3 mapping, and (for the synthetic
     `dispatch_first_syscall` adjacent), the first user instruction
     at RIP is a `syscall` (or a sequence ending in one).
   - A page-fault adjacency: the seam should let an
     `Event::FaultInjected { kind: PageFault { rip, error } }`
     trigger a synthetic `#PF` *before* the simulator returns from
     the `ring3_iretq` shim, so an iret frame whose RIP is in a
     COW-marked page can model "first ring-3 instruction took a
     page-fault."

With that seam in place, the `init_emit_after_iretq` scenario from
this attempt re-targets onto the new event surface: arm an iret frame
matching the production `INIT` ELF's first instruction's RIP and
RSP, dispatch the shim, and assert `Iret64FrameValid` plus
"`Event::FirstSyscallObserved` appears within `K` ticks of `Event::Iret`."
A failing seed under that surface is the first credible computational
analogue of #478.

## References

- [#478](https://github.com/dburkart/vibix/issues/478) — source flake.
- [#724](https://github.com/dburkart/vibix/issues/724) — this attempt.
- [#790](https://github.com/dburkart/vibix/issues/790) — Phase 2.1
  syscall-entry seam (adjacent surface, not the right lever for #478
  but referenced for context).
- [`docs/RFC/0006-host-dst-simulator.md`](../RFC/0006-host-dst-simulator.md)
  §"Concrete flaky targets" — the conditional commitment that authorized
  this hand-off.
- [`docs/design/scheduler-seam.md`](scheduler-seam.md) — the seam this
  Phase 2 surface drove against.
- [`docs/design/simulator.md`](simulator.md) — the v1 simulator
  reference.
- [`simulator/tests/regression_501.rs`](../../simulator/tests/regression_501.rs)
  — the structural template a future #478 regression would mirror once
  the Phase 2.1 surface lands.
- [`kernel/src/init_process.rs`](../../kernel/src/init_process.rs)
  `init_ring3_entry` (~line 199) and
  [`kernel/src/arch/x86_64/syscall.rs`](../../kernel/src/arch/x86_64/syscall.rs)
  `jump_to_ring3` — the kernel-side seam the trap-frame surface would
  intercept.
- [`userspace/init/src/main.rs`](../../userspace/init/src/main.rs)
  `_start` (~line 103) — the userspace side of the failure window.
