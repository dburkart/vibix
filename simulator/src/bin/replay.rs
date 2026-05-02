//! `replay` — host-side simulator CLI (RFC 0006, issues #715/#717/#720).
//!
//! Two argument shapes are supported:
//!
//! ```text
//! cargo run -p simulator --bin replay -- --seed <u64> [--trace-out <path>]
//! cargo run -p simulator --bin replay -- minimize \
//!     --seed <u64> --plan <path> --out <path> [--max-ticks <u64>]
//! ```
//!
//! The first form is the original `replay` stub (#715/#717): it parses
//! flags, prints `unimplemented`, and exits 0. The real per-tick body
//! lands in #716 (run loop) and #717 (trace dump). The argument shape
//! is part of the API contract per RFC 0006 §"Local repro" — downstream
//! auto-engineer tooling and human-facing documentation already cite
//! it, so the names must not drift.
//!
//! The second form (issue #720) drives the two-stage seed minimizer
//! ([`simulator::minimize`]): tick-window binary search followed by
//! `ddmin` over the [`simulator::FaultPlan`]. The "reproduces"
//! predicate is *the simulator panics* — i.e. running with the given
//! seed + (clipped) plan + tick budget produces a `panic!`. This
//! matches the failure mode every Phase 2 invariant violation surfaces
//! as (`SIMULATOR PANIC seed=… tick=…` from the panic hook).
//!
//! `--seed` accepts decimal, `0x`-prefixed hex, and underscored forms
//! (e.g. `0xDEAD_BEEF`, `1234_5678`). Anything else is a usage error
//! that exits with status `2` so shell-side tooling can distinguish a
//! caller mistake from a real simulator failure (which the run-loop
//! PR will surface as exit `1` plus `SIMULATOR PANIC ...`).
//!
//! `--help` / `-h` is treated as a success path (exit `0`, help on
//! stdout) — matching `clap`'s default and the GNU/POSIX convention.
//! It is recognised only when it stands alone as an argument, not
//! when consumed as the value of `--trace-out` (so a literal path of
//! `--help` is still legal, awkward as that may be).

use std::fs;
use std::process::ExitCode;

use simulator::{
    closure_reproducer, minimize, FaultPlan, MinimizeOutput, Simulator, SimulatorConfig, TickWindow,
};

const USAGE: &str = "\
usage: replay --seed <u64> [--trace-out <path>]
       replay minimize --seed <u64> --plan <path> --out <path> [--max-ticks <u64>]

The host-side DST simulator's replay binary.

Top-level form (issue #715/#717): parses arguments and prints \"unimplemented\";
the real run-loop body lands in #716 and the trace dump in #717.

`minimize` subcommand (issue #720): two-stage seed minimizer. Reads a fault
plan JSON file, runs tick-window bisect followed by FaultPlan delta-debug,
and writes the minimized (seed, FaultPlan, tick_window) triple as JSON to
the output path. The \"reproduces\" predicate is a simulator panic.

Options:
  --seed <u64>          Master seed for the run. Accepts decimal,
                        0x-prefixed hex, and underscore separators
                        (e.g. 0xDEAD_BEEF, 1_234_567).
  --trace-out <path>    Path to write the JSON trace dump. Stub
                        accepts and validates this argument but does
                        not yet write a file.
  --plan <path>         (minimize) Path to an input FaultPlan JSON file.
  --out <path>          (minimize) Path to write the minimized output.
  --max-ticks <u64>     (minimize) Initial upper bound on ticks the
                        simulator runs for. Default 1_000_000.
  -h, --help            Print this message.

Exit codes:
  0   Success.
  1   Reserved for simulator failures (run loop, #716; minimize: input
      did not reproduce).
  2   CLI usage error (missing required flag, parse failure).";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(Outcome::Ran) => ExitCode::SUCCESS,
        Ok(Outcome::Help) => {
            // Help goes to stdout (clap convention) and exits 0 so a
            // shell wrapper that asks `replay --help` doesn't see a
            // failure status.
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(CliError::Usage(msg)) => {
            eprintln!("{msg}");
            eprintln!();
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Err(CliError::Runtime(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    /// Non-usage runtime failure (input does not reproduce, IO error,
    /// JSON parse error). Exit code 1 — distinct from CLI usage
    /// errors (exit 2) and from a clean run (exit 0).
    Runtime(String),
}

/// Result of a successful CLI parse + run.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `--help` / `-h` was requested.
    Help,
    /// The stub or subcommand ran successfully.
    Ran,
}

fn run(args: Vec<String>) -> Result<Outcome, CliError> {
    // Subcommand dispatch: `replay minimize ...` is the #720 path,
    // anything else is the top-level #715/#717 stub.
    if let Some(first) = args.first() {
        if first == "minimize" {
            let parsed = parse_minimize(&args[1..])?;
            run_minimize(parsed)?;
            return Ok(Outcome::Ran);
        }
    }
    match parse_args(&args)? {
        ParseOutcome::Help => Ok(Outcome::Help),
        ParseOutcome::Run(parsed) => {
            println!(
                "replay: unimplemented (seed={:#x}, trace_out={})",
                parsed.seed,
                parsed.trace_out.as_deref().unwrap_or("<none>")
            );
            Ok(Outcome::Ran)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    seed: u64,
    trace_out: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum ParseOutcome {
    Help,
    Run(ParsedArgs),
}

fn parse_args(args: &[String]) -> Result<ParseOutcome, CliError> {
    let mut seed: Option<u64> = None;
    let mut trace_out: Option<String> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            // `--help` / `-h` is recognised only at the top level —
            // after `--trace-out` consumes its value below, the next
            // iteration of this loop sees the *following* argument,
            // so a literal `--trace-out --help` still uses `--help`
            // as the path. That is intentional: it preserves the
            // "values are values, flags are flags" boundary.
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "--seed" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from("replay: --seed requires a value"))
                })?;
                if seed.is_some() {
                    return Err(CliError::Usage(String::from(
                        "replay: --seed may be specified only once",
                    )));
                }
                seed = Some(parse_seed(raw)?);
            }
            "--trace-out" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from("replay: --trace-out requires a value"))
                })?;
                if trace_out.is_some() {
                    return Err(CliError::Usage(String::from(
                        "replay: --trace-out may be specified only once",
                    )));
                }
                if raw.is_empty() {
                    return Err(CliError::Usage(String::from(
                        "replay: --trace-out requires a non-empty path",
                    )));
                }
                trace_out = Some(raw.clone());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "replay: unrecognised argument `{other}`"
                )));
            }
        }
    }

    let seed = seed.ok_or_else(|| CliError::Usage(String::from("replay: --seed is required")))?;

    Ok(ParseOutcome::Run(ParsedArgs { seed, trace_out }))
}

fn parse_seed(raw: &str) -> Result<u64, CliError> {
    // Strip underscores so `0xDEAD_BEEF` and `1_234_567` parse the
    // same way Rust integer literals do. The replay seed is always
    // copy-pasted from a panic message or a tracked seed file, so
    // matching the source-literal form is the path of least
    // friction for humans.
    let cleaned: String = raw.chars().filter(|c| *c != '_').collect();

    let parsed = if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        cleaned.parse::<u64>()
    };

    parsed.map_err(|e| CliError::Usage(format!("replay: --seed `{raw}` is not a valid u64: {e}")))
}

#[derive(Debug, PartialEq, Eq)]
struct MinimizeArgs {
    seed: u64,
    plan_path: String,
    out_path: String,
    max_ticks: u64,
}

const MINIMIZE_DEFAULT_MAX_TICKS: u64 = 1_000_000;

fn parse_minimize(args: &[String]) -> Result<MinimizeArgs, CliError> {
    let mut seed: Option<u64> = None;
    let mut plan: Option<String> = None;
    let mut out: Option<String> = None;
    let mut max_ticks: Option<u64> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--seed" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from("replay minimize: --seed requires a value"))
                })?;
                if seed.is_some() {
                    return Err(CliError::Usage(String::from(
                        "replay minimize: --seed may be specified only once",
                    )));
                }
                seed = Some(parse_seed(raw)?);
            }
            "--plan" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from("replay minimize: --plan requires a value"))
                })?;
                if plan.is_some() {
                    return Err(CliError::Usage(String::from(
                        "replay minimize: --plan may be specified only once",
                    )));
                }
                if raw.is_empty() {
                    return Err(CliError::Usage(String::from(
                        "replay minimize: --plan requires a non-empty path",
                    )));
                }
                plan = Some(raw.clone());
            }
            "--out" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from("replay minimize: --out requires a value"))
                })?;
                if out.is_some() {
                    return Err(CliError::Usage(String::from(
                        "replay minimize: --out may be specified only once",
                    )));
                }
                if raw.is_empty() {
                    return Err(CliError::Usage(String::from(
                        "replay minimize: --out requires a non-empty path",
                    )));
                }
                out = Some(raw.clone());
            }
            "--max-ticks" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from(
                        "replay minimize: --max-ticks requires a value",
                    ))
                })?;
                if max_ticks.is_some() {
                    return Err(CliError::Usage(String::from(
                        "replay minimize: --max-ticks may be specified only once",
                    )));
                }
                let cleaned: String = raw.chars().filter(|c| *c != '_').collect();
                let v = cleaned.parse::<u64>().map_err(|e| {
                    CliError::Usage(format!(
                        "replay minimize: --max-ticks `{raw}` is not a valid u64: {e}"
                    ))
                })?;
                if v == 0 {
                    return Err(CliError::Usage(String::from(
                        "replay minimize: --max-ticks must be > 0",
                    )));
                }
                max_ticks = Some(v);
            }
            "-h" | "--help" => {
                // Print usage and request a help-style exit. The
                // outer `run` reads the usage banner from `Outcome::Help`,
                // not from a returned error, so we surface it via a
                // sentinel `Usage` with an empty message that the
                // caller does not show. Simpler: just print and exit.
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "replay minimize: unrecognised argument `{other}`"
                )));
            }
        }
    }

    let seed =
        seed.ok_or_else(|| CliError::Usage(String::from("replay minimize: --seed is required")))?;
    let plan_path =
        plan.ok_or_else(|| CliError::Usage(String::from("replay minimize: --plan is required")))?;
    let out_path =
        out.ok_or_else(|| CliError::Usage(String::from("replay minimize: --out is required")))?;
    let max_ticks = max_ticks.unwrap_or(MINIMIZE_DEFAULT_MAX_TICKS);

    Ok(MinimizeArgs {
        seed,
        plan_path,
        out_path,
        max_ticks,
    })
}

/// Run the simulator on a fresh thread with the given config and
/// return `true` iff the run panicked.
///
/// `Simulator::new` installs a per-thread `task::env` slot that panics
/// on a second install; minimization needs to run hundreds of
/// reproductions, so each one gets its own thread. We catch the
/// panic via `catch_unwind` rather than `panic = "abort"` — the
/// simulator crate ships with the workspace's default unwind panic
/// strategy on host builds (only the bare-metal kernel image uses
/// abort).
fn run_one_panics(seed: u64, plan: &FaultPlan, hi: u64) -> bool {
    let plan = plan.clone();
    std::thread::spawn(move || {
        // `catch_unwind` requires `UnwindSafe`; the simulator owns
        // only `&'static` mocks + a `Vec`-shaped trace, both of which
        // are unwind-safe. We use `AssertUnwindSafe` here because the
        // closure mutably reaches `cfg.fault_plan` through a
        // pass-by-value `cfg`, which the type system flags as
        // potentially-unsound across an unwind boundary even though
        // there is no shared state to corrupt.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let mut cfg = SimulatorConfig::with_seed(seed);
            cfg.fault_plan = plan;
            // Cap at the requested tick budget; the minimizer always
            // passes its `hi` here.
            cfg.max_ticks = hi;
            let mut sim = Simulator::new(seed, cfg);
            sim.run_for(hi);
        }));
        result.is_err()
    })
    .join()
    .unwrap_or(false)
}

fn run_minimize(args: MinimizeArgs) -> Result<(), CliError> {
    let plan_text = fs::read_to_string(&args.plan_path).map_err(|e| {
        CliError::Runtime(format!(
            "replay minimize: cannot read --plan `{}`: {e}",
            args.plan_path
        ))
    })?;
    let plan = FaultPlan::from_json(&plan_text).map_err(|e| {
        CliError::Runtime(format!(
            "replay minimize: cannot parse --plan `{}`: {e}",
            args.plan_path
        ))
    })?;

    // Build the panic-detecting reproducer. The minimizer's
    // `Reproducer::reproduces` callback receives the (already
    // tick-clipped) plan and tick window; we run the simulator under
    // `catch_unwind` and report `true` iff it panicked.
    let mut rep = closure_reproducer(|seed: u64, plan: &FaultPlan, w: TickWindow| {
        run_one_panics(seed, plan, w.hi)
    });

    let initial_window = TickWindow::full(args.max_ticks);
    let out = minimize(&mut rep, args.seed, plan, initial_window).map_err(CliError::Runtime)?;

    let json = encode_minimize_output(&out);
    fs::write(&args.out_path, json).map_err(|e| {
        CliError::Runtime(format!(
            "replay minimize: cannot write --out `{}`: {e}",
            args.out_path
        ))
    })?;

    eprintln!(
        "replay minimize: done — plan {} entries, window [{}, {}), {} reproduction calls",
        out.plan.entries().len(),
        out.tick_window.lo,
        out.tick_window.hi,
        out.calls,
    );
    Ok(())
}

/// Encode a [`MinimizeOutput`] as a small JSON document.
///
/// The schema is deliberately minimal — `seed`, `plan` (the same
/// schema [`FaultPlan::to_json`] writes), and `tick_window`
/// (`{lo, hi}`). A `minimize_schema_version = 1` field at the head
/// pins the wire form against future changes.
fn encode_minimize_output(out: &MinimizeOutput) -> String {
    let plan_json = out.plan.to_json_string();
    format!(
        "{{\"minimize_schema_version\": 1, \"seed\": {seed}, \"plan\": {plan}, \
         \"tick_window\": {{\"lo\": {lo}, \"hi\": {hi}}}, \"calls\": {calls}}}",
        seed = out.seed,
        plan = plan_json,
        lo = out.tick_window.lo,
        hi = out.tick_window.hi,
        calls = out.calls,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn unwrap_run(outcome: ParseOutcome) -> ParsedArgs {
        match outcome {
            ParseOutcome::Run(p) => p,
            ParseOutcome::Help => panic!("expected Run, got Help"),
        }
    }

    #[test]
    fn parses_decimal_seed() {
        let parsed = unwrap_run(parse_args(&args(&["--seed", "42"])).unwrap());
        assert_eq!(parsed.seed, 42);
        assert_eq!(parsed.trace_out, None);
    }

    #[test]
    fn parses_hex_seed_with_underscores() {
        let parsed = unwrap_run(parse_args(&args(&["--seed", "0xDEAD_BEEF"])).unwrap());
        assert_eq!(parsed.seed, 0xDEAD_BEEF);
    }

    #[test]
    fn parses_decimal_seed_with_underscores() {
        let parsed = unwrap_run(parse_args(&args(&["--seed", "1_234_567"])).unwrap());
        assert_eq!(parsed.seed, 1_234_567);
    }

    #[test]
    fn parses_uppercase_hex_prefix() {
        let parsed = unwrap_run(parse_args(&args(&["--seed", "0XAA"])).unwrap());
        assert_eq!(parsed.seed, 0xAA);
    }

    #[test]
    fn parses_trace_out() {
        let parsed =
            unwrap_run(parse_args(&args(&["--seed", "1", "--trace-out", "/tmp/t.json"])).unwrap());
        assert_eq!(parsed.seed, 1);
        assert_eq!(parsed.trace_out.as_deref(), Some("/tmp/t.json"));
    }

    #[test]
    fn missing_seed_is_usage_error() {
        let err = parse_args(&args(&[])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("--seed is required"), "got: {msg}");
    }

    #[test]
    fn unknown_flag_is_usage_error() {
        let err = parse_args(&args(&["--seed", "1", "--bogus"])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("unrecognised argument"), "got: {msg}");
    }

    #[test]
    fn dangling_seed_flag_is_usage_error() {
        let err = parse_args(&args(&["--seed"])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("--seed requires a value"), "got: {msg}");
    }

    #[test]
    fn empty_trace_out_is_usage_error() {
        let err = parse_args(&args(&["--seed", "1", "--trace-out", ""])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(
            msg.contains("--trace-out requires a non-empty path"),
            "got: {msg}"
        );
    }

    #[test]
    fn bad_seed_is_usage_error() {
        let err = parse_args(&args(&["--seed", "notanint"])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("not a valid u64"), "got: {msg}");
    }

    #[test]
    fn help_flag_returns_help_outcome() {
        // `--help` and `-h` must succeed (clap convention, exit 0).
        assert_eq!(parse_args(&args(&["-h"])).unwrap(), ParseOutcome::Help);
        assert_eq!(parse_args(&args(&["--help"])).unwrap(), ParseOutcome::Help);
    }

    #[test]
    fn duplicate_seed_is_usage_error() {
        let err = parse_args(&args(&["--seed", "1", "--seed", "2"])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(
            msg.contains("--seed may be specified only once"),
            "got: {msg}"
        );
    }

    #[test]
    fn duplicate_trace_out_is_usage_error() {
        let err = parse_args(&args(&[
            "--seed",
            "1",
            "--trace-out",
            "/tmp/a.json",
            "--trace-out",
            "/tmp/b.json",
        ]))
        .unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(
            msg.contains("--trace-out may be specified only once"),
            "got: {msg}"
        );
    }

    #[test]
    fn help_does_not_swallow_trace_out_value() {
        // Regression cover for the CodeRabbit review on PR #767:
        // a literal `--help` after `--trace-out` should be consumed
        // as the path value, not as a help request.
        let parsed =
            unwrap_run(parse_args(&args(&["--seed", "1", "--trace-out", "--help"])).unwrap());
        assert_eq!(parsed.trace_out.as_deref(), Some("--help"));
    }

    // --- `minimize` subcommand argument parsing ---

    #[test]
    fn minimize_parses_required_args() {
        let parsed = parse_minimize(&args(&[
            "--seed",
            "0xDEAD_BEEF",
            "--plan",
            "/tmp/p.json",
            "--out",
            "/tmp/o.json",
        ]))
        .unwrap();
        assert_eq!(parsed.seed, 0xDEAD_BEEF);
        assert_eq!(parsed.plan_path, "/tmp/p.json");
        assert_eq!(parsed.out_path, "/tmp/o.json");
        assert_eq!(parsed.max_ticks, MINIMIZE_DEFAULT_MAX_TICKS);
    }

    #[test]
    fn minimize_parses_max_ticks_override() {
        let parsed = parse_minimize(&args(&[
            "--seed",
            "1",
            "--plan",
            "/tmp/p.json",
            "--out",
            "/tmp/o.json",
            "--max-ticks",
            "65_536",
        ]))
        .unwrap();
        assert_eq!(parsed.max_ticks, 65_536);
    }

    #[test]
    fn minimize_missing_seed_is_usage_error() {
        let err =
            parse_minimize(&args(&["--plan", "/tmp/p.json", "--out", "/tmp/o.json"])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("--seed is required"), "got: {msg}");
    }

    #[test]
    fn minimize_missing_plan_is_usage_error() {
        let err = parse_minimize(&args(&["--seed", "1", "--out", "/tmp/o.json"])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("--plan is required"), "got: {msg}");
    }

    #[test]
    fn minimize_missing_out_is_usage_error() {
        let err = parse_minimize(&args(&["--seed", "1", "--plan", "/tmp/p.json"])).unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("--out is required"), "got: {msg}");
    }

    #[test]
    fn minimize_zero_max_ticks_is_usage_error() {
        let err = parse_minimize(&args(&[
            "--seed",
            "1",
            "--plan",
            "/tmp/p.json",
            "--out",
            "/tmp/o.json",
            "--max-ticks",
            "0",
        ]))
        .unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("--max-ticks must be > 0"), "got: {msg}");
    }

    #[test]
    fn minimize_unknown_flag_is_usage_error() {
        let err = parse_minimize(&args(&[
            "--seed",
            "1",
            "--plan",
            "/tmp/p.json",
            "--out",
            "/tmp/o.json",
            "--bogus",
        ]))
        .unwrap_err();
        let CliError::Usage(msg) = err else {
            panic!("expected Usage")
        };
        assert!(msg.contains("unrecognised argument"), "got: {msg}");
    }

    #[test]
    fn encode_minimize_output_round_trip_shape() {
        // Sanity: the encoder produces well-formed JSON that the
        // FaultPlan parser accepts as the inner `plan` object.
        let plan = FaultPlan::from_entries(vec![(
            42,
            simulator::FaultEvent::WakeupReorder { within_tick: 1 },
        )]);
        let out = MinimizeOutput {
            seed: 0xCAFE,
            plan: plan.clone(),
            tick_window: TickWindow { lo: 10, hi: 50 },
            calls: 17,
        };
        let s = encode_minimize_output(&out);
        assert!(s.contains("\"minimize_schema_version\": 1"));
        assert!(s.contains("\"seed\": 51966"));
        assert!(s.contains("\"lo\": 10"));
        assert!(s.contains("\"hi\": 50"));
        assert!(s.contains("\"calls\": 17"));
        // The plan substring must itself be valid plan JSON.
        let needle = "\"plan\": ";
        let plan_start = s.find(needle).expect("plan field") + needle.len();
        // Find the end of the plan object by counting braces.
        let bytes = s.as_bytes();
        let mut depth = 0i32;
        let mut end = plan_start;
        for (i, b) in bytes[plan_start..].iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = plan_start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let plan_substr = &s[plan_start..end];
        let parsed = FaultPlan::from_json(plan_substr).expect("plan re-parses");
        assert_eq!(parsed, plan);
    }
}
