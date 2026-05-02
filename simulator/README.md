# `simulator/` — host-side DST simulator

This crate is the host-only deterministic simulator for the vibix kernel
(RFC 0006). It consumes the `sched-mock` seam landed in
[RFC 0005](../docs/RFC/0005-scheduler-irq-seam.md) and converts today's
flaky concurrency bugs into reproducible
`cargo test -- --seed=0xDEADBEEF` failures.

For the design rationale and full envelope, read the RFC. For the
as-shipped one-page reference, read [`docs/design/simulator.md`](../docs/design/simulator.md).
This file is a quick map of how the simulator is wired into CI.

## CI surface

The simulator runs in two tiers:

| Tier        | Trigger             | Workflow                                    | Wall-clock budget |
|-------------|---------------------|---------------------------------------------|-------------------|
| Fast suite  | every PR + push     | `.github/workflows/ci.yml` (`host-build`)   | **≤ 90 s**        |
| Nightly     | scheduled (04:17Z)  | `.github/workflows/nightly-simulator.yml`   | **≤ 30 min**      |

The fast suite gates every merge. The nightly sweep finds randomized
failures that the fast tier's bounded coverage misses.

## Performance budget (RFC 0006 §"CI perf budget")

| Workload                                   | Per-PR fast suite              | Nightly sweep                                          |
|--------------------------------------------|--------------------------------|--------------------------------------------------------|
| Realistic per-tick cost                    | 5–20 µs                        | same                                                   |
| Per-PR target                              | **100 seeds × 10k ticks ≈ 10–20 s** | n/a                                              |
| Nightly target                             | n/a                            | **10k seeds × 100k ticks**, rayon-parallel ≈ **10–20 min** |
| Regression-detection seed list (this crate)| **`tests/seeds/regression.txt` (~50 seeds × 10k ticks ≈ 5–10 s)** | rolled into nightly |
| Observed (warm cache, this crate, debug profile) | **~0.04 s** for 40 seeds × 10k ticks (`fast_suite.rs`) | **~10 s** for 10k cases × 10k ticks (`nightly_sweep.rs`) |

The "observed" row is what the current implementation hits on a
4-core GitHub-hosted runner with a warm cargo cache. Per-tick cost
sits well below the RFC's 5 µs floor because the empty-FaultPlan path
takes the trace-recorder fast path; the higher 5–20 µs RFC numbers
account for fault dispatch + invariant checking under load.

The fast suite has 6× headroom on the 60 s `regression_corpus_runs_under_fast_suite_budget`
guard (see `simulator/tests/fast_suite.rs`), which keeps CI runner
variance from making the suite a flake source itself.

## Test layout

| File                                  | Tier      | Purpose                                                            |
|---------------------------------------|-----------|--------------------------------------------------------------------|
| `src/lib.rs` (lib unit tests)         | Fast      | Run-loop, RNG, trace, fault-plan, invariant unit + smoke tests     |
| `src/proptest_model.rs` (`#[cfg(test)]`) | Fast   | 32-case `proptest_state_machine` reference-model sweep             |
| `tests/fast_suite.rs`                 | Fast      | Bounded regression-seed corpus, 10k ticks each, ≤ 60 s budget       |
| `tests/regression_501.rs`             | Fast      | Captured-repro guard for #501 (fork/exec/wait)                     |
| `tests/nightly_sweep.rs` (`#[ignore]`) | Nightly  | 10k-case randomized exploration off a single master seed           |

## Reproducing a nightly failure locally

The nightly workflow uploads a `sim-trace-<git_rev>[-dirty]/` artifact
on every run (green or red). The artifact contains:

```
SUMMARY.txt       ← top-level status, master_seed, failing seed/tick
panic_log.txt     ← captured stderr including the panic-hook output
fault_plan.json   ← FaultPlan for the failing case (empty for v1 sweeps)
trace.json        ← v1 placeholder; full trace lands when #717's `--trace-out` does
```

To reproduce a failing master seed locally:

```sh
VIBIX_SIM_MASTER_SEED=0xDEAD_BEEF \
    cargo test -p simulator --test nightly_sweep -- \
    --ignored nightly_randomized_exploration_sweep
```

The `master_seed` is recorded in three places — the workflow log, the
artifact's `SUMMARY.txt`, and the auto-filed P0 issue's body.

## Trace attribution under dirty trees

Per RFC 0006 §"Trace attribution under dirty trees" (Security review B2):
every artifact filename includes the git rev and a `dirty` suffix when
`git status --porcelain` reports a non-empty working tree.

CI runs from a clean checkout, so the `dirty` suffix should never
appear on a scheduled run. The suffix exists so that local artifacts
captured against a dirty tree (e.g. a developer attaching a trace dump
to a bug report) are unambiguously labeled.

## Adding a regression seed

Edit `tests/seeds/regression.txt` and add the new seed (decimal,
`0x`-prefixed hex, or underscored forms). The next `cargo test -p
simulator --test fast_suite` invocation picks it up automatically. Keep
the corpus in the ~10–200 seed range; the
`corpus_parses_and_is_non_empty` guard fails the build outside that
band.
