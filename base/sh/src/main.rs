#![feature(restricted_std)]

mod builtins;
mod exec;
mod expand;
mod glob;
mod lexer;
mod parser;
mod redirect;

use builtins::EXIT_REQUESTED;
use exec::execute_list;
use expand::Environment;

fn main() {
    let mut env = Environment::new();

    // Initialize $PATH with a sensible default.
    env.set("PATH", "/bin:/usr/bin", Some(true));

    // Set the shell PID.
    env.shell_pid = std::process::id();
    env.arg0 = "sh".to_string();

    // Import environment variables from the process environment.
    for (key, value) in std::env::vars() {
        env.set(&key, &value, Some(true));
    }

    // Check for -c flag (command string execution).
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "-c" {
        let input = &args[2];
        // Set positional parameters from remaining args.
        if args.len() > 3 {
            env.arg0 = args[3].clone();
            env.positional = args[4..].to_vec();
        }
        let status = run_input(input, &mut env);
        if status == EXIT_REQUESTED {
            std::process::exit(env.last_status);
        }
        std::process::exit(status);
    }

    // Interactive / stdin mode: read lines and execute.
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let is_tty = false; // TODO: detect interactive terminal

    if is_tty {
        eprint!("$ ");
    }

    for line in stdin.lock().lines() {
        match line {
            Ok(input) => {
                if input.is_empty() {
                    if is_tty {
                        eprint!("$ ");
                    }
                    continue;
                }
                let status = run_input(&input, &mut env);
                if status == EXIT_REQUESTED {
                    std::process::exit(env.last_status);
                }
                if is_tty {
                    eprint!("$ ");
                }
            }
            Err(_) => break,
        }
    }

    // Exit with the last command's status (preserves status on stdin EOF).
    std::process::exit(env.last_status);
}

/// Parse and execute a single input string.
fn run_input(input: &str, env: &mut Environment) -> i32 {
    let list = match parser::parse(input) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("sh: {e}");
            env.last_status = 2;
            return 2;
        }
    };

    let status = execute_list(&list, env);
    if status != EXIT_REQUESTED {
        env.last_status = status;
    }
    status
}
