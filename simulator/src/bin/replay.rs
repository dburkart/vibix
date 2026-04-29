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
        Ok(()) => ExitCode::SUCCESS,
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

fn run(args: Vec<String>) -> Result<(), CliError> {
    let parsed = parse_args(&args)?;
    println!(
        "replay: unimplemented (seed={:#x}, trace_out={})",
        parsed.seed,
        parsed.trace_out.as_deref().unwrap_or("<none>")
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    seed: u64,
    trace_out: Option<String>,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, CliError> {
    // Bare `--help` / `-h` short-circuits to a usage error so the help
    // text gets printed and the process exits non-zero — matches the
    // convention `clap` uses by default and keeps the stub honest
    // about not being a real CLI yet.
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Err(CliError::Usage(String::from("replay: help requested")));
    }

    let mut seed: Option<u64> = None;
    let mut trace_out: Option<String> = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--seed" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from("replay: --seed requires a value"))
                })?;
                seed = Some(parse_seed(raw)?);
            }
            "--trace-out" => {
                let raw = iter.next().ok_or_else(|| {
                    CliError::Usage(String::from("replay: --trace-out requires a value"))
                })?;
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

    Ok(ParsedArgs { seed, trace_out })
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

    #[test]
    fn parses_decimal_seed() {
        let parsed = parse_args(&args(&["--seed", "42"])).unwrap();
        assert_eq!(parsed.seed, 42);
        assert_eq!(parsed.trace_out, None);
    }

    #[test]
    fn parses_hex_seed_with_underscores() {
        let parsed = parse_args(&args(&["--seed", "0xDEAD_BEEF"])).unwrap();
        assert_eq!(parsed.seed, 0xDEAD_BEEF);
    }

    #[test]
    fn parses_decimal_seed_with_underscores() {
        let parsed = parse_args(&args(&["--seed", "1_234_567"])).unwrap();
        assert_eq!(parsed.seed, 1_234_567);
    }

    #[test]
    fn parses_uppercase_hex_prefix() {
        let parsed = parse_args(&args(&["--seed", "0XAA"])).unwrap();
        assert_eq!(parsed.seed, 0xAA);
    }

    #[test]
    fn parses_trace_out() {
        let parsed = parse_args(&args(&["--seed", "1", "--trace-out", "/tmp/t.json"])).unwrap();
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
    fn help_flag_short_circuits() {
        let err = parse_args(&args(&["-h"])).unwrap_err();
        let CliError::Usage(msg) = err;
        assert!(msg.contains("help requested"), "got: {msg}");
    }
}
