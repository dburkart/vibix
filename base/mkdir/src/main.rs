#![feature(restricted_std)]

#[cfg(not(test))]
mod syscalls;

use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        eprintln!("mkdir: missing operand");
        return ExitCode::from(1);
    }

    let mut status: u8 = 0;
    for path in &args[1..] {
        if let Err(e) = fs::create_dir(path) {
            eprintln!("mkdir: {path}: {e}");
            status = 1;
        }
    }

    ExitCode::from(status)
}
