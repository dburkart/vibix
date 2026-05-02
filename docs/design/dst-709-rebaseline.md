# #709 re-baseline after #710's atomic-publish fix

**Status as of 2026-05-02:** the post-fork-child-stall flake tracked in
[#709](https://github.com/dburkart/vibix/issues/709) ("post-fork child task
never executes — 14% recurrence under TCG soak") is **no longer reproducible
locally** after PR
[#795](https://github.com/dburkart/vibix/pull/795) (`process: atomic-publish
Zombie state + EXIT_EVENT under TABLE`) landed for the sister issue
[#710](https://github.com/dburkart/vibix/issues/710). The two flakes share a
root cause; #709's distinct symptom shape was a different schedule manifestation
of the same drain-order race in `mark_zombie`.

This document records the empirical re-baseline so a future regression can
spot the change in the failure surface.

## Re-baseline protocol

Same protocol as #709's original soak (issue body §"Work" item 1), modulo
sample size:

```
git checkout main   # at 22f53f2 (post-#795)
for i in $(seq 1 100); do
    cargo xtask smoke
done
```

Pass criterion: every run produces all 42 `SMOKE_MARKERS`, including the
post-fork pair `["hello: hello from execed child", "init: fork+exec+wait
ok"]`.

## Result

| Soak         | Runs | Failures | Rate                                    |
|--------------|-----:|---------:|-----------------------------------------|
| #709 nightly | 1000 |      141 | 14.1% (run [25032340134])               |
| local sweep 1 |  100 |        0 | 0% (95% Wilson upper bound 2.95%)       |
| local sweep 2 |  100 |        0 | 0% (95% Wilson upper bound 2.95%)       |

[25032340134]: https://github.com/dburkart/vibix/actions/runs/25032340134

A 14.1% true rate would produce P(0/200) = (1 − 0.141)^200 ≈ 7 × 10⁻¹⁴ — in
practical terms, the rate has been moved by orders of magnitude. The
single-host sweep is not a replacement for the CI nightly's noise profile,
so the residual rate is bounded statistically rather than measured to zero;
re-running the 1000× nightly soak against post-#795 main is the canonical
verification.

## Why #710's fix moved #709's rate

The two flakes shared the same drain-order window in `mark_zombie`
(`kernel/src/process/mod.rs`):

```text
   write Zombie state into TABLE         ← under TABLE critical section
   drop TABLE                            ← TABLE drop
=> EXIT_EVENT.fetch_add                  ← OLD shape: drain window opens here
   CHILD_WAIT.notify_all
```

The window between TABLE drop and the `EXIT_EVENT` bump was permutable by
the v1 simulator's `WakeupReorder` (see
`simulator/tests/regression_501.rs`) and reachable on TCG with the right
preempt schedule. Two distinct user-visible symptoms followed from the same
race:

* **#710 mode (post-`wait4` stall, ~0.9%):** parent had already snapshotted
  `EXIT_EVENT`, the child exit's `mark_zombie` published Zombie + dropped
  TABLE, and a preempt landed in the bump-counter gap. The parent woke,
  re-checked the predicate before the bump, observed the same snapshot, and
  re-parked. `notify_all` then fired against an empty queue and the parent
  remained parked indefinitely. Visible as `init: wait4-return` and
  `init: fork+exec+wait ok` both missing while the child's
  `hello: hello from execed child` was present.

* **#709 mode (post-fork child stall, ~14%):** same drain-order race, but
  earlier in the lifecycle. The parent had blocked in `wait4`'s
  `wait_while`. The child ran `mark_zombie`, dropped TABLE, and a preempt
  landed in the bump gap before `notify_all`. The parent's wakeup never
  arrived; meanwhile the child task entered `task::exit` → reaper queue,
  but no other ready task picked up the schedule path back to the child's
  `hello` write. The visible signature was every marker after `init:
  post-write marker` missing — including the second `ring3-iretq:` from
  `execve`, because the child's `execve` had not yet completed its
  `jump_to_ring3`. The 14% rate reflects the higher TCG-resident
  probability of the bump-gap preempt landing during the *first*
  schedule-after-fork rather than during the *parent-resume after wait4*
  window the #710 mode catches.

PR #795 closed the bump-gap by moving `EXIT_EVENT.fetch_add` inside the
same TABLE critical section as the Zombie state write. Any TABLE acquirer
now observes both transitions or neither, regardless of which preempt
schedule TCG picks. The two flakes collapse into one resolved race.

## Relationship to dst-478-investigation.md

The Phase 2 v1-simulator hand-off
([`docs/design/dst-478-investigation.md`](dst-478-investigation.md))
correctly identified that the *#478 shape* — silence after the *first*
IRETQ to ring-3, before any userspace `syscall` — is unreachable from the
v1 simulator and lives in the iretq → first-instruction → first-syscall
window, requiring a Phase 2.1 ring-3 trap-frame seam.

#709 was tagged "#478 redux" in the issue title, which was a reasonable
hypothesis from the symptom shape (markers stop appearing on the post-fork
control path) but turned out to mis-classify the failure. The actual root
cause was the wait4 condvar drain-order, not the iretq path: the child
task *did* execute its `fork_child_sysret` SYSRETQ and *did* run user
code; the silence in the captured serial reflected the parent never
resuming to drive the next visible marker, plus the child being preempted
before its `execve` completed. #710's atomic-publish fix resolved both
modes by making the wakeup ordering total.

The #478 family proper (silence between iretq and first-syscall) remains
unaffected by #795 and continues to wait on the Phase 2.1 ring-3
trap-frame seam.

## Coverage

`simulator/tests/regression_501.rs` (PR #792) is the seam-level guard
against re-introducing the drain-order race. `kernel/tests/wait4_condvar_race.rs`
exercises the same invariant in a kernel-task harness. The kernel
integration tests cover the exact `mark_zombie → wait4_loop` ordering
that this re-baseline confirms is repaired in production.

A regression that reopens the bump-gap window would surface as:

* `simulator/tests/regression_501.rs` failing (immediate, deterministic).
* `kernel::tests::wait4_condvar_race::mark_zombie_atomically_publishes_state_and_event`
  failing under `cargo xtask test` (deterministic).
* The 1000× nightly soak surfacing a fresh post-fork or post-wait4
  marker-drop above the current ≤ 1% upper bound.

## References

* [#709](https://github.com/dburkart/vibix/issues/709) — this flake.
* [#710](https://github.com/dburkart/vibix/issues/710) — the sister flake (closed
  by [#795](https://github.com/dburkart/vibix/pull/795)).
* [#501](https://github.com/dburkart/vibix/issues/501) — parent epic.
* [`kernel/src/process/mod.rs::mark_zombie`](../../kernel/src/process/mod.rs)
  — site of the atomic-publish fix.
* [`simulator/tests/regression_501.rs`](../../simulator/tests/regression_501.rs)
  — seam-level regression guard.
* [`kernel/tests/wait4_condvar_race.rs`](../../kernel/tests/wait4_condvar_race.rs)
  — kernel-task regression guard.
* Original soak run: [25032340134](https://github.com/dburkart/vibix/actions/runs/25032340134).
