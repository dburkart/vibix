#![feature(restricted_std)]

#[cfg(not(test))]
mod syscalls;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let all = args.iter().any(|a| a == "-a");

    if all {
        println!("vibix vibix 0.1.0 x86_64");
    } else {
        println!("vibix");
    }

    ExitCode::from(0)
}
