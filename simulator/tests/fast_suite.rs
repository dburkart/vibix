//! Fast-suite regression sweep — RFC 0006 §"CI perf budget", issue #723.
//!
//! Reads the bounded seed corpus at `simulator/tests/seeds/regression.txt`
//! and runs the simulator's run loop on each seed for a fixed tick budget,
//! demanding every safety + liveness invariant from the v1 set holds.
//!
//! # Performance target
//!
//! Per the RFC perf table (§"CI perf budget"):
//!
//! | Workload                        | Budget           |
//! |---------------------------------|------------------|
//! | Regression-detection seed list  | ~50 × 10k ≈ 5–10s|
//!
//! Combined with the existing `cargo test -p simulator` lib-test surface
//! (smoke + invariant + proptest 32-case sweep) the per-PR fast-suite
//! wall-clock target is **≤ 90 s**, well above the measured cost.
//!
//! # Why a `tests/`-bin and not a `#[test]` inside `lib.rs`
//!
//! The kernel-side `install_sim_env` panics if called twice on the same
//! thread. `cargo test` shares its worker pool across every `#[test]`
//! function in a single test binary, so back-to-back `Simulator::new`
//! calls inside one binary must each spawn their own thread (the same
//! pattern `simulator/src/lib.rs::tests::on_fresh_thread` uses). This
//! file does the same — every seed runs on a fresh worker thread that
//! installs, runs, joins, and is dropped before the next seed starts.
//!
//! # Updating the corpus
//!
//! Add a new seed to `simulator/tests/seeds/regression.txt`. The next
//! `cargo test -p simulator --test fast_suite` invocation picks it up
//! automatically — there is no per-seed test function to maintain.

use simulator::{Simulator, SimulatorConfig};

/// Per-seed tick budget. Sized so 40-50 seeds run under the RFC's
/// ~5–10s slice of the 90s fast-suite budget. A 10k-tick run on the
/// host triple is ~5–10 ms wall-clock with the empty FaultPlan; the
/// seed loop is dominated by thread spawn/join overhead, not by tick
/// throughput.
const TICKS_PER_SEED: u64 = 10_000;

/// Path to the corpus file relative to the simulator crate root. Cargo
/// sets `CARGO_MANIFEST_DIR` to the simulator crate's root for
/// integration tests, which is the stable anchor for relative IO.
const CORPUS_RELATIVE_PATH: &str = "tests/seeds/regression.txt";

fn corpus_path() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR set by cargo for integration tests");
    std::path::PathBuf::from(manifest).join(CORPUS_RELATIVE_PATH)
}

/// Parse the seed corpus. Tolerates `#` comments, blank lines, decimal,
/// `0x`/`0X`-prefixed hex, and `_` separators (matching `replay --seed`).
fn parse_corpus(text: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cleaned: String = line.chars().filter(|c| *c != '_').collect();
        let parsed = if let Some(hex) = cleaned
            .strip_prefix("0x")
            .or_else(|| cleaned.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            cleaned.parse::<u64>()
        };
        match parsed {
            Ok(seed) => out.push(seed),
            Err(e) => panic!(
                "seeds/regression.txt:{}: cannot parse `{}` as u64: {}",
                lineno + 1,
                line,
                e
            ),
        }
    }
    out
}

/// Run one seed's tick budget on a fresh thread, returning the
/// resulting trace length on success or the violation string on
/// failure. The worker-thread sandbox keeps `install_sim_env`'s
/// "called twice on the same thread" panic out of the cross-seed
/// loop.
fn run_seed(seed: u64) -> Result<usize, String> {
    std::thread::spawn(move || -> Result<usize, String> {
        let cfg = SimulatorConfig::with_seed(seed);
        let mut sim = Simulator::new(seed, cfg);
        // Use `step_checked` so a violation surfaces as an `Err` rather
        // than panicking the worker — keeps the cross-seed loop cheap
        // (no panic-unwind cost per pass).
        for _ in 0..TICKS_PER_SEED {
            if let Err(v) = sim.step_checked() {
                return Err(format!("seed={seed:#x}: {v}"));
            }
        }
        sim.check_liveness()
            .map_err(|v| format!("seed={seed:#x}: liveness {v}"))?;
        Ok(sim.trace().len())
    })
    .join()
    .map_err(|panic| {
        let msg = panic
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic>".to_string());
        format!("seed={seed:#x}: worker panic: {msg}")
    })?
}

/// The corpus file must parse, must be non-empty, and must be in the
/// ~50-seed range the RFC's perf table commits to. A careless edit
/// that drops every seed (e.g. a global comment-out) would silently
/// turn the fast suite into a no-op; assert the size up-front.
#[test]
fn corpus_parses_and_is_non_empty() {
    let path = corpus_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read corpus at {}: {e}", path.display()));
    let seeds = parse_corpus(&text);
    assert!(
        !seeds.is_empty(),
        "regression seed corpus at {} parsed to zero seeds",
        path.display()
    );
    // The RFC's "≈50 seeds × 10k ticks ≈ 5–10s" budget assumes the list
    // stays in roughly that range. A future cleanup that pruned to <10
    // seeds would erase regression coverage; one that grew past 200
    // would blow the per-PR wall-clock budget without anyone noticing.
    // Bound from both sides so either direction trips a test rather
    // than an opaque CI-time regression.
    assert!(
        (10..=200).contains(&seeds.len()),
        "regression seed corpus has {} seeds; RFC 0006 §\"CI perf budget\" \
         pins this list at ~50 seeds. Update the budget assertion in \
         tests/fast_suite.rs::corpus_parses_and_is_non_empty if the \
         change is intentional.",
        seeds.len()
    );
}

/// Every seed in the regression corpus must complete its `TICKS_PER_SEED`
/// budget without a v1 invariant violation.
///
/// This is the per-PR "have we regressed against the deterministic
/// floor?" check. The corpus is the empty-FaultPlan baseline — a
/// failure here means the kernel-side seam exposed by `sched-mock`
/// drifted in a way that breaks an invariant under no fault injection
/// at all, which is a P0-class regression on the simulator itself.
#[test]
fn regression_corpus_passes_invariants() {
    let text = std::fs::read_to_string(corpus_path()).expect("corpus readable");
    let seeds = parse_corpus(&text);
    let mut failures = Vec::new();
    for seed in &seeds {
        if let Err(msg) = run_seed(*seed) {
            failures.push(msg);
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} seeds failed:\n{}",
        failures.len(),
        seeds.len(),
        failures.join("\n")
    );
}

/// The fast suite's wall-clock budget must hold against the run-loop's
/// per-tick cost. We measure the in-binary cost (excluding cargo /
/// linker overhead the per-PR job pays once) and demand it stay under
/// 60 s — a generous fraction of the 90 s budget the issue body pins.
///
/// A regression here typically means a `step_inner` change pushed
/// per-tick cost up; the trace recorder, the fault-plan drain, or a
/// new `BTreeMap` lookup added on the hot path are the usual
/// suspects. The 60 s limit is intentionally loose: CI runners vary
/// in speed, and this test must not be a flake source itself.
#[test]
fn regression_corpus_runs_under_fast_suite_budget() {
    let text = std::fs::read_to_string(corpus_path()).expect("corpus readable");
    let seeds = parse_corpus(&text);
    let start = std::time::Instant::now();
    for seed in &seeds {
        run_seed(*seed).expect("seed must pass — see regression_corpus_passes_invariants");
    }
    let elapsed = start.elapsed();
    // 60 s ceiling; RFC budget is ~5–10 s. Leaving 6× headroom keeps
    // CI runner variance from making this a flaky guard.
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "fast-suite regression sweep took {:?} for {} seeds; \
         RFC 0006 §\"CI perf budget\" pins this at ~5–10 s and the \
         guard at 60 s. Investigate per-tick cost regression.",
        elapsed,
        seeds.len()
    );
}
