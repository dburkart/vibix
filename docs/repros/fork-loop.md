# Fork-loop reproducer harness

Tracks epic [#501], implements sub-issue [#506].  Amplifies the ~50 %-rate
fork/exec/wait hang bisected to PR #206 into a deterministic, fast-to-boot
reproducer.

[#501]: https://github.com/dburkart/vibix/issues/501
[#506]: https://github.com/dburkart/vibix/issues/506

## What it does

Replaces PID 1 with a userspace binary (`userspace/repro_fork/`) that runs
a tight `fork → child execve → parent wait4` loop for `CYCLES` iterations
(default 500).  Every 50 cycles it writes `repro: cycle K alive` to serial;
every cycle it reads the TSC before and after and prints a watchdog
marker if a single cycle overruns its budget.

The kernel is unchanged.  Limine still loads `/boot/userspace_init.elf`
as PID 1 — we just ship a different binary there when building for
reproduction.

## Run it

From the repo root:

```
cargo xtask repro-fork
```

Or via the CI shim (identical behavior, easier to wire into shell
orchestration):

```
scripts/repro-fork.sh
scripts/repro-fork.sh --runs 20   # local soak — fails fast on first hang
```

Success: a final `repro: fork loop complete cycles=500` line and QEMU
exits 0.  Failure: any of —

- `repro: WATCHDOG fork stuck cycle=K dtsc=...` — a single cycle
  overran the TSC budget; the kernel was almost certainly hung.
- `repro: fork failed cycle=K ret=-N` — `fork()` returned an errno.
- `repro: wait4 failed cycle=K ret=-N` — `wait4()` returned an errno.
- `KERNEL PANIC: ...` — the kernel panicked.
- Heartbeat gap > 60 s with no new `repro:` line — the xtask wrapper
  kills QEMU and reports a stall.

## Tuning

- `REPRO_FORK_CYCLES=<N>`: overrides the compile-time cycle count.  Set
  to a large value for soak runs.  (Implemented as `option_env!` inside
  the binary, so cargo rebuilds when the value changes.)
- The per-cycle TSC budget is a compile-time constant
  (`STALL_TSC_BUDGET` in `userspace/repro_fork/src/main.rs`).  Bump it
  if unaccelerated CI QEMU is hitting spurious watchdog trips on a
  healthy kernel.

## Expected reproducibility

The original flake's per-boot hit rate is ~50 %.  With 500 cycles per
boot the expected per-run hit rate rises to
`1 - (1 - p)^500` for any per-cycle hang probability `p`.  Even at
`p = 0.01` that's ~99.3 %; at `p = 0.001` it's ~39 %, still a dramatic
amplification over the one-fork-per-boot baseline.

Actual local observations should be recorded in the PR that introduces
this harness and in the tracking issues that consume it (#504, #505).

## Scope / what this does NOT do

- **Does not edit kernel source.**  Issues #502, #504, #505 own the
  kernel side of the sprint; this harness is strictly userspace + ISO
  + wrapper.
- **Does not wire itself into CI yaml.**  Issue #507 owns `.github/`.
  The wrapper script exists at a stable path so #507 can call it.
- **Does not claim deterministic reproduction of the #206 flake.**

## CI integration

The `smoke-soak` workflow (`.github/workflows/smoke-soak.yml`) drives
`scripts/repro-fork.sh` in a loop as its amplifier — one script
invocation per iteration, with `SOAK_COUNT` iterations per job run
(default 100) and a `SOAK_MIN_PASS_RATE` threshold (default 80 %).
Nightly `schedule` and manual `workflow_dispatch` runs exercise this
path today; the `pull_request` trigger is still gated off while the
fork flake is live (see #517).  Changes to this harness — either the
wrapper script or `userspace/repro_fork/` — trigger the workflow's
path filter so the soak runs on any PR that touches them.

  The harness amplifies opportunity to hit the hang; whether it trips
  on clean `main` depends on the underlying rate.  If a follow-up
  discovers the harness needs `serial_println!` instrumentation from
  #502 to reproduce reliably, that's expected — file a follow-up
  rather than retrofitting this PR.
