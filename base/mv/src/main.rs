#![feature(restricted_std)]

#[cfg(not(test))]
mod syscalls;

use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("usage: mv <src> <dst>");
        return ExitCode::from(1);
    }

    let src = &args[1];
    let dst = &args[2];

    if let Err(e) = fs::rename(src, dst) {
        eprintln!("mv: {src} -> {dst}: {e}");
        return ExitCode::from(1);
    }

    ExitCode::from(0)
}
