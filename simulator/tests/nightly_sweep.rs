//! Nightly sweep — RFC 0006 §"CI perf budget", issue #723.
//!
//! Runs a randomized exploration sweep at much higher iteration count
//! than the per-PR fast suite. The issue body pins the gate at
//! "proptest 10_000 iterations on randomized master seed; ~30 min
//! budget." The run-style gate sits behind `#[ignore]` so a developer's
//! `cargo test -p simulator` invocation does not pay the 10k-iteration
//! cost; CI's `nightly-simulator.yml` workflow runs it explicitly via
//! `--ignored`.
//!
//! # Master-seed source
//!
//! Per RFC 0006 §"Reproducibility Envelope": every randomized run
//! records its master seed so a failing nightly produces an
//! immediately-replayable `(seed, FaultPlan)` pair. The master seed
//! is taken from `VIBIX_SIM_MASTER_SEED` if set; otherwise it is
//! derived from the system clock at test entry (the only point in
//! the simulator pipeline where we deliberately consume host
//! entropy — and only for the *master seed*, never for any
//! decision-axis byte). The chosen seed is logged before every run
//! so the workflow's failure-artifact step can recover it from the
//! log even if the panic-hook cell is somehow clobbered first.
//!
//! # Iteration count
//!
//! The default is 10 000 cases. The `VIBIX_SIM_NIGHTLY_CASES` env
//! var overrides this so a developer can run a quick manual sweep
//! locally (e.g. `VIBIX_SIM_NIGHTLY_CASES=200`) without editing the
//! source. A value of `0` is treated as "use the default" — the
//! `unwrap_or` below collapses missing-env and parse-failure into a
//! single fallback.

use std::time::Instant;

use simulator::{Simulator, SimulatorConfig};

/// Default nightly iteration count. Pulled out as a `const` so the
/// `nightly-simulator.yml` workflow's step summary can cite the
/// expected number.
const NIGHTLY_DEFAULT_CASES: usize = 10_000;

/// Per-iteration tick budget for the randomized exploration sweep.
/// 100k ticks per seed matches the RFC's nightly perf table
/// ("10k seeds × 100k ticks" — we run ≤10k seeds within a 30-min
/// budget; reaching 100k ticks per seed at the same per-tick cost
/// would blow the budget, so we cap at 10k for now and revisit
/// once rayon-over-seeds lands).
const NIGHTLY_TICKS_PER_SEED: u64 = 10_000;

/// Parse a u64 master seed from a string. Accepts decimal,
/// `0x`/`0X`-prefixed hex, and `_` separators (matching `replay --seed`).
fn parse_master_seed(s: &str) -> Result<u64, std::num::ParseIntError> {
    let cleaned: String = s.chars().filter(|c| *c != '_').collect();
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        cleaned.parse::<u64>()
    }
}

/// Resolve the master seed for this run.
///
/// The recorded seed must survive into the panic message (via
/// `Simulator::new`'s panic-hook install) so a failing case is
/// immediately replayable. We log to stderr before any seed-based
/// work begins so even an early-panic case has the master seed
/// captured in the workflow log.
fn master_seed() -> u64 {
    if let Ok(s) = std::env::var("VIBIX_SIM_MASTER_SEED") {
        return parse_master_seed(&s).expect("VIBIX_SIM_MASTER_SEED parses as u64");
    }
    // Fallback: nanosecond-resolution time. The master seed is the
    // *only* host-entropy consumer in the simulator pipeline; once
    // it's logged, every downstream byte derives from it via the
    // simulator's ChaCha8 sub-streams.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs() ^ u64::from(now.subsec_nanos()).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Resolve the iteration count for this run.
fn nightly_cases() -> usize {
    std::env::var("VIBIX_SIM_NIGHTLY_CASES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(NIGHTLY_DEFAULT_CASES)
}

/// Step `seed` for `NIGHTLY_TICKS_PER_SEED` ticks; return Err on a
/// safety/liveness violation. Same fresh-thread sandbox the fast
/// suite uses.
fn run_one(seed: u64) -> Result<(), String> {
    std::thread::spawn(move || -> Result<(), String> {
        let cfg = SimulatorConfig::with_seed(seed);
        let mut sim = Simulator::new(seed, cfg);
        for _ in 0..NIGHTLY_TICKS_PER_SEED {
            if let Err(v) = sim.step_checked() {
                return Err(format!("seed={seed:#x}: {v}"));
            }
        }
        sim.check_liveness()
            .map_err(|v| format!("seed={seed:#x}: liveness {v}"))?;
        Ok(())
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

/// Derive the per-iteration seed from a master seed and case index
/// using splitmix64 — same primitive `simulator::SimRng::rng_for`
/// uses internally.
fn derive_seed(master: u64, idx: usize) -> u64 {
    let mut x = master.wrapping_add((idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// The nightly randomized exploration gate.
///
/// Marked `#[ignore]` so a developer's plain `cargo test -p simulator`
/// does not pay its cost. CI's `nightly-simulator.yml` workflow runs
/// `cargo test -p simulator --test nightly_sweep -- --ignored` to
/// trigger it.
///
/// On failure, the panic-hook installed by `Simulator::new` emits a
/// `SIMULATOR PANIC seed=<master> tick=<N>` line that the workflow's
/// artifact-upload step parses to populate the `seed` field in the
/// uploaded artifact. The same line, plus the master seed echoed
/// here, is sufficient to replay the failing case locally:
///
/// ```sh
/// VIBIX_SIM_MASTER_SEED=<master> \
///     cargo test -p simulator --test nightly_sweep -- \
///     --ignored nightly_randomized_exploration_sweep
/// ```
#[test]
#[ignore = "nightly randomized sweep — run manually with --ignored \
             or via .github/workflows/nightly-simulator.yml"]
fn nightly_randomized_exploration_sweep() {
    let master = master_seed();
    let cases = nightly_cases();
    eprintln!(
        "nightly_sweep: master_seed={master:#x} cases={cases} \
         ticks_per_case={NIGHTLY_TICKS_PER_SEED}"
    );

    let start = Instant::now();
    let mut failures: Vec<String> = Vec::new();
    for i in 0..cases {
        let seed = derive_seed(master, i);
        if let Err(msg) = run_one(seed) {
            failures.push(format!("case {i}: {msg}"));
            // Stop after the first failure — the `(seed, FaultPlan,
            // trace.json, panic_log)` artifact for one failing seed
            // is the deliverable; piling up more is just noise. The
            // workflow's auto-issue step then has a single, unambiguous
            // master+case to file against.
            break;
        }
        // Progress beat every 1k cases so the workflow log shows
        // forward progress through the 30-min budget.
        if (i + 1).is_multiple_of(1_000) {
            eprintln!(
                "nightly_sweep: {}/{} cases complete ({:.1}s elapsed)",
                i + 1,
                cases,
                start.elapsed().as_secs_f64()
            );
        }
    }
    let elapsed = start.elapsed();
    eprintln!(
        "nightly_sweep: master_seed={master:#x} cases={cases} \
         elapsed={:.1}s failures={}",
        elapsed.as_secs_f64(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "nightly_sweep: master_seed={master:#x}: {}/{} cases failed:\n{}",
        failures.len(),
        cases,
        failures.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `derive_seed` must be deterministic and pairwise-distinct across
    /// adjacent cases — guards against an accidental "seed never
    /// changes" regression that would silently turn the sweep into a
    /// 10k-times-the-same-seed loop.
    #[test]
    fn derive_seed_is_deterministic_and_distinct() {
        let s0 = derive_seed(0xCAFE_F00D, 0);
        let s1 = derive_seed(0xCAFE_F00D, 1);
        let s0_again = derive_seed(0xCAFE_F00D, 0);
        assert_eq!(s0, s0_again, "derive_seed must be deterministic");
        assert_ne!(s0, s1, "adjacent cases must derive distinct seeds");
        // Defence in depth: a one-bit perturbation in the master seed
        // must avalanche through the case-0 derivation.
        assert_ne!(derive_seed(0xCAFE_F00D, 0), derive_seed(0xCAFE_F00C, 0));
    }

    /// `parse_master_seed()` honors the canonical seed forms so a
    /// failing nightly is replayable from the recorded master.
    /// Tests the parse path without mutating the process env (which
    /// would race with `cargo test`'s parallel runner).
    #[test]
    fn parse_master_seed_accepts_canonical_forms() {
        assert_eq!(parse_master_seed("0xDEAD_BEEF").unwrap(), 0xDEAD_BEEF);
        assert_eq!(parse_master_seed("0xdead_beef").unwrap(), 0xDEAD_BEEF);
        assert_eq!(parse_master_seed("0XDEAD").unwrap(), 0xDEAD);
        assert_eq!(parse_master_seed("12345").unwrap(), 12345);
        assert_eq!(parse_master_seed("1_234_567").unwrap(), 1_234_567);
        assert!(parse_master_seed("notanint").is_err());
        assert!(parse_master_seed("0xZZZ").is_err());
    }
}
