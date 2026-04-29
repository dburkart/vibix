//! `replay` — host-side simulator CLI stub (RFC 0006, issue #715).
//!
//! The committed argument shape is
//!
//! ```text
//! cargo run -p simulator --bin replay -- --seed <u64> [--trace-out <path>]
//! ```
//!
//! Today this binary parses those flags, prints `unimplemented`, and
//! exits 0. The real replay path lands in #716 (run loop) and #717
//! (trace dump). The argument shape is part of the API contract per
//! RFC 0006 §"Local repro" — downstream auto-engineer tooling and
//! human-facing documentation already cite it, so the names must not
//! drift.
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

use std::process::ExitCode;

const USAGE: &str = "\
usage: replay --seed <u64> [--trace-out <path>]

The host-side DST simulator's replay binary. Today this is a stub
that only parses arguments and prints \"unimplemented\"; the real
run-loop body lands in #716 and the trace dump in #717.

Options:
  --seed <u64>          Master seed for the run. Accepts decimal,
                        0x-prefixed hex, and underscore separators
                        (e.g. 0xDEAD_BEEF, 1_234_567).
  --trace-out <path>    Path to write the JSON trace dump. Stub
                        accepts and validates this argument but does
                        not yet write a file.
  -h, --help            Print this message.

Exit codes:
  0   Success (today: always, since the body is unimplemented).
  1   Reserved for simulator failures (run loop, #716).
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
    }
}

#[derive(Debug)]
enum CliError {
    Usage(String),
}

/// Result of a successful CLI parse + run.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `--help` / `-h` was requested.
    Help,
    /// The stub ran (and printed `unimplemented`).
    Ran,
}

fn run(args: Vec<String>) -> Result<Outcome, CliError> {
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
        let CliError::Usage(msg) = err;
        assert!(msg.contains("--seed is required"), "got: {msg}");
    }

    #[test]
    fn unknown_flag_is_usage_error() {
        let err = parse_args(&args(&["--seed", "1", "--bogus"])).unwrap_err();
        let CliError::Usage(msg) = err;
        assert!(msg.contains("unrecognised argument"), "got: {msg}");
    }

    #[test]
    fn dangling_seed_flag_is_usage_error() {
        let err = parse_args(&args(&["--seed"])).unwrap_err();
        let CliError::Usage(msg) = err;
        assert!(msg.contains("--seed requires a value"), "got: {msg}");
    }

    #[test]
    fn empty_trace_out_is_usage_error() {
        let err = parse_args(&args(&["--seed", "1", "--trace-out", ""])).unwrap_err();
        let CliError::Usage(msg) = err;
        assert!(
            msg.contains("--trace-out requires a non-empty path"),
            "got: {msg}"
        );
    }

    #[test]
    fn bad_seed_is_usage_error() {
        let err = parse_args(&args(&["--seed", "notanint"])).unwrap_err();
        let CliError::Usage(msg) = err;
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
        let CliError::Usage(msg) = err;
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
        let CliError::Usage(msg) = err;
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
}
