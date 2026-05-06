#![feature(restricted_std)]

#[cfg(not(test))]
mod syscalls;

use std::env;
use std::fs;
use std::process::ExitCode;

fn stat_path(path: &str) -> u8 {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("stat: {path}: {e}");
            return 1;
        }
    };

    let file_type = if meta.is_dir() {
        "directory"
    } else if meta.is_symlink() {
        "symbolic link"
    } else {
        "regular file"
    };

    println!("  File: {path}");
    println!("  Size: {}", meta.len());
    println!(" Type: {file_type}");
    println!("Inode: unknown");
    println!("Links: unknown");

    0
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        eprintln!("stat: missing operand");
        return ExitCode::from(1);
    }

    let mut status: u8 = 0;
    for path in &args[1..] {
        let s = stat_path(path);
        if s != 0 {
            status = s;
        }
    }

    ExitCode::from(status)
}
