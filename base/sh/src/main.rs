#![feature(restricted_std)]

mod builtins;
mod exec;
mod expand;
mod glob;
#[cfg_attr(test, allow(dead_code))]
mod job;
mod lexer;
mod parser;
mod redirect;

use builtins::EXIT_REQUESTED;
use exec::{execute_list, execute_list_with_jobs};
use expand::Environment;
use job::JobTable;

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

    // Detect if stdin is a terminal. On vibix, isatty may not be
    // available via std, so we check the TERM variable or fall back
    // to assuming interactive when stdin is not redirected.
    let is_tty = std::env::var("TERM").is_ok();

    // Create the job table for interactive mode.
    let mut jobs = JobTable::new();

    // When interactive, install signal handlers so the shell
    // ignores SIGINT/SIGTSTP (they go to the foreground process
    // group instead).
    if is_tty {
        job::install_interactive_signals();
        eprint!("$ ");
    }

    for line in stdin.lock().lines() {
        match line {
            Ok(input) => {
                if input.is_empty() {
                    if is_tty {
                        // Reap background jobs and show notifications.
                        job::reap_children(&mut jobs);
                        job::notify_completed_jobs(&mut jobs);
                        eprint!("$ ");
                    }
                    continue;
                }
                let status = run_input_with_jobs(&input, &mut env, &mut jobs);
                if status == EXIT_REQUESTED {
                    std::process::exit(env.last_status);
                }
                if is_tty {
                    // Reap background jobs and show notifications.
                    job::reap_children(&mut jobs);
                    job::notify_completed_jobs(&mut jobs);
                    eprint!("$ ");
                }
            }
            Err(_) => break,
        }
    }

    // Exit with the last command's status (preserves status on stdin EOF).
    std::process::exit(env.last_status);
}

/// Parse and execute a single input string (no job control).
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

/// Parse and execute a single input string with job control.
fn run_input_with_jobs(input: &str, env: &mut Environment, jobs: &mut JobTable) -> i32 {
    let list = match parser::parse(input) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("sh: {e}");
            env.last_status = 2;
            return 2;
        }
    };

    let status = execute_list_with_jobs(&list, env, jobs);
    if status != EXIT_REQUESTED {
        env.last_status = status;
    }
    status
}
