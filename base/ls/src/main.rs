#![feature(restricted_std)]

#[cfg(not(test))]
mod syscalls;

use std::env;
use std::fs;
use std::process;

fn list_dir(path: &str) -> i32 {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("ls: {path}: {e}");
            return 1;
        }
    };

    let mut names: Vec<(String, bool)> = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = entry
                    .file_type()
                    .map(|ft| ft.is_dir())
                    .unwrap_or(false);
                names.push((name, is_dir));
            }
            Err(e) => {
                eprintln!("ls: {path}: {e}");
                return 1;
            }
        }
    }

    names.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, is_dir) in &names {
        if *is_dir {
            println!("{name}/");
        } else {
            println!("{name}");
        }
    }

    0
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut status = 0;

    if args.len() <= 1 {
        status = list_dir(".");
    } else {
        let show_header = args.len() > 2;
        for (i, path) in args[1..].iter().enumerate() {
            if show_header {
                if i > 0 {
                    println!();
                }
                println!("{path}:");
            }
            let s = list_dir(path);
            if s != 0 {
                status = s;
            }
        }
    }

    process::exit(status);
}
