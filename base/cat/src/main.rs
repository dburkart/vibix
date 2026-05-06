#![feature(restricted_std)]

#[cfg(not(test))]
mod syscalls;

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process;

fn cat_reader<R: Read>(mut reader: R, stdout: &mut io::StdoutLock<'_>) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n])?;
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut status = 0;

    if args.len() <= 1 {
        // No arguments: read stdin to stdout.
        let stdin = io::stdin();
        let stdin = stdin.lock();
        if let Err(e) = cat_reader(stdin, &mut stdout) {
            eprintln!("cat: {e}");
            process::exit(1);
        }
    } else {
        for path in &args[1..] {
            if path == "-" {
                let stdin = io::stdin();
                let stdin = stdin.lock();
                if let Err(e) = cat_reader(stdin, &mut stdout) {
                    eprintln!("cat: -: {e}");
                    status = 1;
                }
            } else {
                match File::open(path) {
                    Ok(file) => {
                        if let Err(e) = cat_reader(file, &mut stdout) {
                            eprintln!("cat: {path}: {e}");
                            status = 1;
                        }
                    }
                    Err(e) => {
                        eprintln!("cat: {path}: {e}");
                        status = 1;
                    }
                }
            }
        }
    }

    process::exit(status);
}
