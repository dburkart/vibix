//! Command executor for the POSIX shell.
//!
//! This module is the core runtime loop: it takes the AST from the
//! parser, expands variables and globs, applies redirections, dispatches
//! builtins or forks+execves external commands, and handles pipelines
//! and compound lists.
//!
//! ## Execution model
//!
//! - **Simple commands**: expand words, check for builtins, otherwise
//!   fork+execve. Variable-only commands (no command name) set variables
//!   in the current environment.
//! - **Pipelines**: create pipes between stages, fork each stage, wire
//!   stdin/stdout via dup2, wait for all children.
//! - **Lists**: execute pipelines left-to-right with short-circuit
//!   evaluation for `&&` and `||`.
//! - **Subshells**: fork, execute the list in the child, wait.
//!
//! ## PATH search
//!
//! When a command name does not contain `/`, the executor searches each
//! directory in `$PATH` (colon-separated) for an executable file. If no
//! match is found, a "command not found" diagnostic is printed and exit
//! status 127 is set.

use crate::builtins::{is_builtin, run_builtin, EXIT_REQUESTED};
use crate::expand::{expand_word, field_split, Environment};
use crate::glob::glob_expand_words;
use crate::parser::{Command, List, ListOp, Pipeline, SimpleCommand};

// ── Extern C declarations ──────────────────────────────────────────

#[cfg(not(test))]
extern "C" {
    fn fork() -> i32;
    fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32;
    fn pipe(pipefd: *mut i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn wait4(pid: i32, wstatus: *mut i32, options: i32, rusage: *const u8) -> i32;
    fn access(pathname: *const u8, mode: i32) -> i32;
    fn __errno_location() -> *mut i32;
}

/// access(2) X_OK flag.
#[cfg(not(test))]
const X_OK: i32 = 1;

#[cfg(not(test))]
fn get_errno() -> i32 {
    unsafe { *__errno_location() }
}

// ── Public API ─────────────────────────────────────────────────────

/// Execute a parsed list (the top-level AST node).
///
/// Returns the exit status of the last command executed. The caller
/// should update `env.last_status` with this value.
pub fn execute_list(list: &List, env: &mut Environment) -> i32 {
    if list.pipelines.is_empty() {
        return env.last_status;
    }

    let mut status = execute_pipeline(&list.pipelines[0], env);
    if status == EXIT_REQUESTED {
        return EXIT_REQUESTED;
    }
    env.last_status = status;

    for i in 0..list.ops.len() {
        let op = list.ops[i];
        let next = &list.pipelines[i + 1];

        match op {
            ListOp::Semi => {
                status = execute_pipeline(next, env);
                if status == EXIT_REQUESTED {
                    return EXIT_REQUESTED;
                }
                env.last_status = status;
            }
            ListOp::And => {
                if status == 0 {
                    status = execute_pipeline(next, env);
                    if status == EXIT_REQUESTED {
                        return EXIT_REQUESTED;
                    }
                    env.last_status = status;
                }
                // else: short-circuit, keep current status
            }
            ListOp::Or => {
                if status != 0 {
                    status = execute_pipeline(next, env);
                    if status == EXIT_REQUESTED {
                        return EXIT_REQUESTED;
                    }
                    env.last_status = status;
                }
                // else: short-circuit, keep current status
            }
        }
    }

    status
}

// ── Pipeline execution ─────────────────────────────────────────────

/// Execute a pipeline of one or more commands.
///
/// For a single command, no pipes are created. For multi-command
/// pipelines, pipes connect each stage's stdout to the next stage's
/// stdin. The exit status is that of the last command in the pipeline.
fn execute_pipeline(pipeline: &Pipeline, env: &mut Environment) -> i32 {
    let n = pipeline.commands.len();
    if n == 0 {
        return 0;
    }

    // Single command — no pipes needed.
    if n == 1 {
        return execute_command(&pipeline.commands[0], env);
    }

    // Multi-command pipeline.
    execute_pipeline_multi(pipeline, env)
}

/// Execute a multi-stage pipeline (2+ commands).
#[cfg(not(test))]
fn execute_pipeline_multi(pipeline: &Pipeline, env: &mut Environment) -> i32 {
    let n = pipeline.commands.len();
    let mut child_pids: Vec<i32> = Vec::with_capacity(n);
    let mut prev_read_fd: i32 = -1;

    for i in 0..n {
        let is_last = i == n - 1;

        // Create a pipe for all stages except the last.
        let mut pipe_fds: [i32; 2] = [-1, -1];
        if !is_last {
            let ret = unsafe { pipe(pipe_fds.as_mut_ptr()) };
            if ret < 0 {
                eprintln!("sh: pipe: failed (errno {})", get_errno());
                return 1;
            }
        }

        let pid = unsafe { fork() };
        if pid < 0 {
            eprintln!("sh: fork: failed (errno {})", get_errno());
            return 1;
        }

        if pid == 0 {
            // Child process.

            // Wire stdin from previous pipe's read end (if not first stage).
            if prev_read_fd >= 0 {
                unsafe {
                    dup2(prev_read_fd, 0);
                    close(prev_read_fd);
                }
            }

            // Wire stdout to this pipe's write end (if not last stage).
            if !is_last {
                unsafe {
                    dup2(pipe_fds[1], 1);
                    close(pipe_fds[0]);
                    close(pipe_fds[1]);
                }
            }

            // Execute the command in the child.
            let status = execute_command(&pipeline.commands[i], env);
            std::process::exit(status);
        }

        // Parent: bookkeeping.
        child_pids.push(pid);

        // Close the previous read fd — the child inherited it.
        if prev_read_fd >= 0 {
            unsafe {
                close(prev_read_fd);
            }
        }

        // Close the write end — only the child needs it.
        if !is_last {
            unsafe {
                close(pipe_fds[1]);
            }
            prev_read_fd = pipe_fds[0];
        }
    }

    // Wait for all children. The exit status of the pipeline is the
    // exit status of the last command.
    let mut last_status = 0;
    for (i, &pid) in child_pids.iter().enumerate() {
        let mut wstatus: i32 = 0;
        unsafe {
            wait4(pid, &mut wstatus, 0, std::ptr::null());
        }
        let exit_code = ((wstatus as u32) >> 8) & 0xFF;
        if i == child_pids.len() - 1 {
            last_status = exit_code as i32;
        }
    }

    last_status
}

/// Test stub for multi-stage pipelines — not exercised in host unit
/// tests since fork/pipe are not available.
#[cfg(test)]
fn execute_pipeline_multi(_pipeline: &Pipeline, _env: &mut Environment) -> i32 {
    0
}

// ── Command dispatch ───────────────────────────────────────────────

/// Execute a single command (simple or subshell).
fn execute_command(cmd: &Command, env: &mut Environment) -> i32 {
    match cmd {
        Command::Simple(sc) => execute_simple(sc, env),
        Command::Subshell { body, redirects } => execute_subshell(body, redirects, env),
    }
}

// ── Subshell execution ─────────────────────────────────────────────

/// Execute a subshell: fork, run the list in the child, wait.
#[cfg(not(test))]
fn execute_subshell(
    body: &List,
    redirects: &[crate::parser::Redirect],
    env: &mut Environment,
) -> i32 {
    let pid = unsafe { fork() };
    if pid < 0 {
        eprintln!("sh: fork: failed (errno {})", get_errno());
        return 1;
    }
    if pid == 0 {
        // Child: apply redirections and execute the list.
        if !redirects.is_empty() {
            if let Err(e) = crate::redirect::apply_redirects(redirects) {
                eprintln!("sh: {e}");
                std::process::exit(1);
            }
        }
        let status = execute_list(body, env);
        std::process::exit(status);
    }

    // Parent: wait for the child.
    let mut wstatus: i32 = 0;
    unsafe {
        wait4(pid, &mut wstatus, 0, std::ptr::null());
    }
    let exit_code = ((wstatus as u32) >> 8) & 0xFF;
    exit_code as i32
}

/// Test stub for subshell — execute inline (no fork).
#[cfg(test)]
fn execute_subshell(
    body: &List,
    _redirects: &[crate::parser::Redirect],
    env: &mut Environment,
) -> i32 {
    execute_list(body, env)
}

// ── Simple command execution ───────────────────────────────────────

/// Execute a simple command.
///
/// 1. Expand words (variable expansion, field splitting, globbing).
/// 2. If no command name, apply assignments to the environment.
/// 3. If the command is a builtin, run it in-process with redirections
///    saved and restored.
/// 4. Otherwise, fork and execve.
fn execute_simple(sc: &SimpleCommand, env: &mut Environment) -> i32 {
    // Expand all words.
    let mut expanded_words: Vec<String> = Vec::new();
    for word in &sc.words {
        match expand_word(word, env) {
            Ok(expanded) => {
                // Field split the expanded word.
                let ifs = env.get("IFS").map(|s| s.to_string());
                let fields = field_split(&expanded, ifs.as_deref());
                expanded_words.extend(fields);
            }
            Err(e) => {
                eprintln!("sh: {e}");
                return 1;
            }
        }
    }

    // Glob expansion.
    let expanded_words = glob_expand_words(&expanded_words);

    // If no command name, apply assignments.
    if expanded_words.is_empty() {
        for assignment in &sc.assignments {
            if let Some(eq_pos) = assignment.find('=') {
                let name = &assignment[..eq_pos];
                let raw_value = &assignment[eq_pos + 1..];
                let value = match expand_word(raw_value, env) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("sh: {e}");
                        return 1;
                    }
                };
                env.set(name, &value, None);
            }
        }
        return 0;
    }

    let cmd_name = &expanded_words[0];
    let args: Vec<String> = expanded_words[1..].to_vec();

    // Check for builtins.
    if is_builtin(cmd_name) {
        return execute_builtin(cmd_name, &args, &sc.redirects, &sc.assignments, env);
    }

    // External command.
    execute_external(cmd_name, &expanded_words, &sc.redirects, &sc.assignments, env)
}

/// Execute a builtin command with redirect save/restore.
fn execute_builtin(
    name: &str,
    args: &[String],
    redirects: &[crate::parser::Redirect],
    assignments: &[String],
    env: &mut Environment,
) -> i32 {
    // Apply pre-command assignments temporarily for builtins.
    let mut saved_vars: Vec<(String, Option<String>)> = Vec::new();
    for assignment in assignments {
        if let Some(eq_pos) = assignment.find('=') {
            let var_name = &assignment[..eq_pos];
            let raw_value = &assignment[eq_pos + 1..];
            let value = match expand_word(raw_value, env) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("sh: {e}");
                    return 1;
                }
            };
            saved_vars.push((var_name.to_string(), env.get(var_name).map(|s| s.to_string())));
            env.set(var_name, &value, None);
        }
    }

    // Apply redirections.
    let saved_fds: Option<crate::redirect::SavedFds> = if !redirects.is_empty() {
        #[cfg(not(test))]
        {
            match crate::redirect::apply_redirects(redirects) {
                Ok(saved) => Some(saved),
                Err(e) => {
                    eprintln!("sh: {e}");
                    // Restore saved variables.
                    restore_vars(&saved_vars, env);
                    return 1;
                }
            }
        }
        #[cfg(test)]
        {
            let _ = redirects;
            None
        }
    } else {
        None
    };

    let status = run_builtin(name, args, env);

    // Restore redirections.
    if let Some(saved) = saved_fds {
        if let Err(e) = saved.restore() {
            eprintln!("sh: {e}");
        }
    }

    // Restore pre-command assignment variables (builtins only get them
    // temporarily, per POSIX, unless the builtin is a "special builtin").
    // For simplicity, we don't distinguish special vs regular here.
    // cd, export, etc. keep their assignments — for now we leave them.
    // TODO: Distinguish special builtins from regular ones.

    status
}

/// Restore saved variable values.
fn restore_vars(saved: &[(String, Option<String>)], env: &mut Environment) {
    for (name, old_val) in saved.iter().rev() {
        match old_val {
            Some(v) => env.set(name, v, None),
            None => env.unset(name),
        }
    }
}

/// Execute an external command via fork+execve.
#[cfg(not(test))]
fn execute_external(
    cmd_name: &str,
    argv: &[String],
    redirects: &[crate::parser::Redirect],
    assignments: &[String],
    env: &mut Environment,
) -> i32 {
    // Resolve the command path.
    let path = match resolve_command(cmd_name, env) {
        Some(p) => p,
        None => {
            eprintln!("sh: {cmd_name}: command not found");
            return 127;
        }
    };

    let pid = unsafe { fork() };
    if pid < 0 {
        eprintln!("sh: fork: failed (errno {})", get_errno());
        return 1;
    }

    if pid == 0 {
        // Child process.

        // Apply pre-command assignments as exported variables.
        for assignment in assignments {
            if let Some(eq_pos) = assignment.find('=') {
                let name = &assignment[..eq_pos];
                let raw_value = &assignment[eq_pos + 1..];
                let value = match expand_word(raw_value, env) {
                    Ok(v) => v,
                    Err(_) => String::new(),
                };
                env.set(name, &value, Some(true));
            }
        }

        // Apply redirections.
        if !redirects.is_empty() {
            if let Err(e) = crate::redirect::apply_redirects(redirects) {
                eprintln!("sh: {e}");
                std::process::exit(1);
            }
        }

        // Build argv as null-terminated C strings.
        let c_args: Vec<Vec<u8>> = argv
            .iter()
            .map(|a| {
                let mut v = a.as_bytes().to_vec();
                v.push(0);
                v
            })
            .collect();
        let c_ptrs: Vec<*const u8> = c_args
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // Build envp from exported variables.
        let exported = env.exported_vars();
        let c_envs: Vec<Vec<u8>> = exported
            .iter()
            .map(|(k, v)| {
                let mut s = format!("{k}={v}").into_bytes();
                s.push(0);
                s
            })
            .collect();
        let c_env_ptrs: Vec<*const u8> = c_envs
            .iter()
            .map(|e| e.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // Build the null-terminated path.
        let mut path_buf = path.as_bytes().to_vec();
        path_buf.push(0);

        unsafe {
            execve(path_buf.as_ptr(), c_ptrs.as_ptr(), c_env_ptrs.as_ptr());
        }

        // If execve returns, it failed.
        let errno = get_errno();
        eprintln!("sh: {cmd_name}: {}", errno_message(errno));
        if errno == 2 {
            // ENOENT
            std::process::exit(127);
        } else {
            std::process::exit(126);
        }
    }

    // Parent: wait for the child.
    let mut wstatus: i32 = 0;
    unsafe {
        wait4(pid, &mut wstatus, 0, std::ptr::null());
    }
    let exit_code = ((wstatus as u32) >> 8) & 0xFF;
    exit_code as i32
}

/// Test stub for external command execution.
#[cfg(test)]
fn execute_external(
    cmd_name: &str,
    _argv: &[String],
    _redirects: &[crate::parser::Redirect],
    _assignments: &[String],
    _env: &mut Environment,
) -> i32 {
    // In tests, external commands always "not found".
    eprintln!("sh: {cmd_name}: command not found");
    127
}

// ── PATH search ────────────────────────────────────────────────────

/// Resolve a command name to an absolute path.
///
/// If the name contains `/`, it is used as-is (relative or absolute).
/// Otherwise, each directory in `$PATH` is searched for an executable
/// file with that name.
fn resolve_command(name: &str, env: &Environment) -> Option<String> {
    // If the name contains a slash, use it directly.
    if name.contains('/') {
        return Some(name.to_string());
    }

    // Search $PATH.
    let path_var = env.get("PATH").unwrap_or("/bin:/usr/bin");
    for dir in path_var.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let candidate = format!("{dir}/{name}");
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Check if a file exists and is executable.
#[cfg(not(test))]
fn is_executable(path: &str) -> bool {
    let mut path_buf = path.as_bytes().to_vec();
    path_buf.push(0);
    unsafe { access(path_buf.as_ptr(), X_OK) == 0 }
}

/// Test stub — always returns false (no filesystem).
#[cfg(test)]
fn is_executable(_path: &str) -> bool {
    false
}

#[cfg(not(test))]
fn errno_message(errno: i32) -> &'static str {
    match errno {
        1 => "Operation not permitted",
        2 => "No such file or directory",
        13 => "Permission denied",
        _ => "exec failed",
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    fn env() -> Environment {
        Environment::new()
    }

    fn parse_and_exec(input: &str, env: &mut Environment) -> i32 {
        let list = parser::parse(input).unwrap();
        execute_list(&list, env)
    }

    // ── Simple commands (builtins) ─────────────────────────────────

    #[test]
    fn echo_simple() {
        let mut e = env();
        let status = parse_and_exec("echo hello world", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn echo_with_variable() {
        let mut e = env();
        e.set("NAME", "vibix", None);
        let status = parse_and_exec("echo hello $NAME", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn exit_status_tracked() {
        let mut e = env();
        // test -z "notempty" => false => exit 1
        let status = parse_and_exec("test -z notempty", &mut e);
        assert_eq!(status, 1);
        assert_eq!(e.last_status, 1);
    }

    #[test]
    fn exit_status_via_dollar_question() {
        let mut e = env();
        // Run a test that fails, then check $? was updated.
        parse_and_exec("test -z notempty", &mut e);
        assert_eq!(e.last_status, 1);
    }

    // ── Variable assignments ───────────────────────────────────────

    #[test]
    fn assignment_only() {
        let mut e = env();
        let status = parse_and_exec("FOO=bar", &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("FOO"), Some("bar"));
    }

    #[test]
    fn multiple_assignments() {
        let mut e = env();
        let status = parse_and_exec("A=1 B=2", &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("A"), Some("1"));
        assert_eq!(e.get("B"), Some("2"));
    }

    #[test]
    fn assignment_with_expansion() {
        let mut e = env();
        e.set("X", "hello", None);
        let status = parse_and_exec("Y=$X", &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("Y"), Some("hello"));
    }

    // ── Command not found ──────────────────────────────────────────

    #[test]
    fn command_not_found() {
        let mut e = env();
        let status = parse_and_exec("nonexistent_command", &mut e);
        assert_eq!(status, 127);
    }

    #[test]
    fn command_not_found_sets_status() {
        let mut e = env();
        parse_and_exec("nonexistent_command", &mut e);
        assert_eq!(e.last_status, 127);
    }

    // ── Lists with ; ───────────────────────────────────────────────

    #[test]
    fn semicolon_list() {
        let mut e = env();
        let status = parse_and_exec("echo a; echo b; echo c", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn semicolon_list_exit_status_of_last() {
        let mut e = env();
        let status = parse_and_exec("echo a; test -z notempty", &mut e);
        // test -z "notempty" => 1
        assert_eq!(status, 1);
    }

    // ── AND list (&&) ──────────────────────────────────────────────

    #[test]
    fn and_list_both_succeed() {
        let mut e = env();
        let status = parse_and_exec("echo a && echo b", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn and_list_first_fails_short_circuits() {
        let mut e = env();
        // test -z "notempty" fails (1), so echo should NOT run.
        let status = parse_and_exec("test -z notempty && echo b", &mut e);
        assert_eq!(status, 1);
    }

    // ── OR list (||) ───────────────────────────────────────────────

    #[test]
    fn or_list_first_succeeds_short_circuits() {
        let mut e = env();
        // echo succeeds (0), so the test should NOT run.
        let status = parse_and_exec("echo a || test -z notempty", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn or_list_first_fails_runs_second() {
        let mut e = env();
        let status = parse_and_exec("test -z notempty || echo fallback", &mut e);
        assert_eq!(status, 0);
    }

    // ── Mixed list operators ───────────────────────────────────────

    #[test]
    fn and_or_chain() {
        let mut e = env();
        // test -n "hello" => 0, && echo ok => 0, || echo fail should NOT run
        let status = parse_and_exec("test -n hello && echo ok || echo fail", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn and_or_chain_failure_path() {
        let mut e = env();
        // test -z "hello" => 1, && echo ok should NOT run, || echo fallback => 0
        let status = parse_and_exec("test -z hello && echo ok || echo fallback", &mut e);
        assert_eq!(status, 0);
    }

    // ── Subshell ───────────────────────────────────────────────────

    #[test]
    fn subshell_simple() {
        let mut e = env();
        let status = parse_and_exec("(echo hello)", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn subshell_with_list() {
        let mut e = env();
        let status = parse_and_exec("(echo a; echo b)", &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn subshell_exit_status() {
        let mut e = env();
        let status = parse_and_exec("(test -z notempty)", &mut e);
        assert_eq!(status, 1);
    }

    // ── PATH resolution ────────────────────────────────────────────

    #[test]
    fn resolve_command_with_slash() {
        let e = env();
        // A name with `/` is returned as-is.
        assert_eq!(resolve_command("/bin/ls", &e), Some("/bin/ls".to_string()));
        assert_eq!(
            resolve_command("./my_script", &e),
            Some("./my_script".to_string())
        );
    }

    #[test]
    fn resolve_command_not_found() {
        let mut e = env();
        // Set PATH to a non-existent directory.
        e.set("PATH", "/nonexistent", None);
        assert_eq!(resolve_command("ls", &e), None);
    }

    // ── Exit builtin ───────────────────────────────────────────────

    #[test]
    fn exit_returns_sentinel() {
        let mut e = env();
        let status = parse_and_exec("exit 42", &mut e);
        // builtin_exit sets env.last_status to 42, then returns
        // EXIT_REQUESTED. execute_list detects the sentinel and
        // returns it without overwriting env.last_status.
        assert_eq!(status, EXIT_REQUESTED);
        assert_eq!(e.last_status, 42);
    }

    // ── Integration: variable assignment then use ──────────────────

    #[test]
    fn set_and_use_variable() {
        let mut e = env();
        parse_and_exec("X=hello", &mut e);
        assert_eq!(e.get("X"), Some("hello"));
        let status = parse_and_exec("echo $X", &mut e);
        assert_eq!(status, 0);
    }

    // ── Empty input ────────────────────────────────────────────────

    #[test]
    fn empty_input() {
        let mut e = env();
        let status = parse_and_exec("", &mut e);
        assert_eq!(status, 0);
    }

    // ── Newlines as separators ─────────────────────────────────────

    #[test]
    fn newline_separated_commands() {
        let mut e = env();
        let status = parse_and_exec("echo a\necho b", &mut e);
        assert_eq!(status, 0);
    }
}
