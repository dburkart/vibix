#![feature(restricted_std)]

#[cfg(not(test))]
mod syscalls;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => {
            println!("vibix");
        }
        2 if args[1] == "-a" => {
            println!("vibix vibix 0.1.0 x86_64");
        }
        _ => {
            eprintln!("usage: uname [-a]");
            return ExitCode::from(1);
        }
    }

    ExitCode::from(0)
}
