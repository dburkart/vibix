//! Shell built-in commands per POSIX.1-2024 section 2.14.
//!
//! Built-in commands execute within the shell process itself because they
//! need to modify shell state (variables, working directory, etc.) that
//! cannot be changed by a child process.
//!
//! ## Supported builtins
//!
//! - `cd` — change working directory (updates `$PWD`/`$OLDPWD`).
//! - `exit` — exit the shell with an optional status code.
//! - `export` — mark variables for export to child processes.
//! - `unset` — remove shell variables.
//! - `echo` — print arguments to stdout.
//! - `test` / `[` — conditional expressions.
//! - `read` — read a line from stdin into variables.
//! - `exec` — replace the shell process with a command.
//! - `set` — set/unset shell options and positional parameters.
//! - `.` (dot/source) — execute commands from a file in the current
//!   environment.

use crate::expand::Environment;
use crate::job::JobTable;

// ── Builtin dispatch ────────────────────────────────────────────────

/// Returns `true` if `name` is a shell builtin command.
pub fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        "cd" | "exit"
            | "export"
            | "unset"
            | "echo"
            | "test"
            | "["
            | "read"
            | "exec"
            | "set"
            | "."
            | "jobs"
            | "fg"
            | "bg"
    )
}

/// Returns `true` if the builtin requires access to the job table.
pub fn is_job_builtin(name: &str) -> bool {
    matches!(name, "jobs" | "fg" | "bg")
}

/// Execute a builtin command and return its exit status.
///
/// `name` must be a recognized builtin (check with [`is_builtin`] first).
/// `args` are the arguments *after* the command name.
///
/// Returns 0 on success, non-zero on error.
pub fn run_builtin(name: &str, args: &[String], env: &mut Environment) -> i32 {
    match name {
        "cd" => builtin_cd(args, env),
        "exit" => builtin_exit(args, env),
        "export" => builtin_export(args, env),
        "unset" => builtin_unset(args, env),
        "echo" => builtin_echo(args),
        "test" => builtin_test(args),
        "[" => builtin_bracket(args),
        "read" => builtin_read(args, env),
        "exec" => builtin_exec(args, env),
        "set" => builtin_set(args, env),
        "." => builtin_dot(args, env),
        // Job-control builtins without a job table — this path should
        // not normally be taken (exec.rs dispatches them via
        // run_job_builtin instead), but handle gracefully.
        "jobs" | "fg" | "bg" => {
            eprintln!("sh: {name}: no job control");
            1
        }
        _ => {
            eprintln!("sh: {name}: not a builtin");
            1
        }
    }
}

/// Execute a job-control builtin with access to the job table.
pub fn run_job_builtin(name: &str, args: &[String], env: &mut Environment, jobs: &mut JobTable) -> i32 {
    match name {
        "jobs" => builtin_jobs(args, jobs),
        "fg" => builtin_fg(args, env, jobs),
        "bg" => builtin_bg(args, env, jobs),
        _ => run_builtin(name, args, env),
    }
}

// ── cd ──────────────────────────────────────────────────────────────

/// Change the working directory.
///
/// - `cd` (no args) — go to `$HOME`.
/// - `cd -` — go to `$OLDPWD` and print the new directory.
/// - `cd DIR` — go to DIR.
///
/// Updates `$OLDPWD` to the old directory and `$PWD` to the new one.
fn builtin_cd(args: &[String], env: &mut Environment) -> i32 {
    let target = if args.is_empty() {
        match env.get("HOME") {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => {
                eprintln!("sh: cd: HOME not set");
                return 1;
            }
        }
    } else if args[0] == "-" {
        match env.get("OLDPWD") {
            Some(d) if !d.is_empty() => d.to_string(),
            _ => {
                eprintln!("sh: cd: OLDPWD not set");
                return 1;
            }
        }
    } else {
        args[0].clone()
    };

    let print_dir = args.first().map(|a| a.as_str()) == Some("-");
    let status = cd_chdir(&target, env);
    if status == 0 && print_dir {
        println!("{target}");
    }
    status
}

/// Actually perform the chdir and update PWD/OLDPWD.
#[cfg(not(test))]
fn cd_chdir(target: &str, env: &mut Environment) -> i32 {
    // Save old PWD.
    let old_pwd = get_cwd().unwrap_or_default();

    let mut path_buf = target.as_bytes().to_vec();
    path_buf.push(0);
    let ret = unsafe { chdir(path_buf.as_ptr()) };
    if ret != 0 {
        eprintln!("sh: cd: {target}: No such file or directory");
        return 1;
    }

    // Update environment.
    env.set("OLDPWD", &old_pwd, None);
    if let Some(new_pwd) = get_cwd() {
        env.set("PWD", &new_pwd, None);
    }
    0
}

/// Test stub — validate target and update env without syscalls.
#[cfg(test)]
fn cd_chdir(target: &str, env: &mut Environment) -> i32 {
    if target.is_empty() {
        return 1;
    }
    let old_pwd = env.get("PWD").unwrap_or("").to_string();
    env.set("OLDPWD", &old_pwd, None);
    env.set("PWD", target, None);
    0
}

/// Get the current working directory as a String.
#[cfg(not(test))]
fn get_cwd() -> Option<String> {
    let mut buf = [0u8; 4096];
    let ret = unsafe { getcwd(buf.as_mut_ptr(), buf.len()) };
    if ret.is_null() {
        None
    } else {
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..len]).into_owned())
    }
}

// ── exit ────────────────────────────────────────────────────────────

/// Exit the shell with an optional status code.
///
/// - `exit` — exit with `$?` (last exit status).
/// - `exit N` — exit with status N (masked to 0-255).
fn builtin_exit(args: &[String], env: &mut Environment) -> i32 {
    let status = if args.is_empty() {
        env.last_status
    } else {
        match args[0].parse::<i32>() {
            Ok(n) => n & 0xFF,
            Err(_) => {
                eprintln!("sh: exit: {}: numeric argument required", args[0]);
                2
            }
        }
    };

    // In a real shell, this would call std::process::exit(). For now,
    // set the status so the caller can detect the exit request.
    // The caller checks for EXIT_REQUESTED_SENTINEL to know to stop.
    env.last_status = status;
    EXIT_REQUESTED
}

/// Sentinel value returned by `builtin_exit` so the shell executor
/// knows the user typed `exit` (as opposed to a command that happened
/// to return this status). Chosen to be outside the normal 0-255 range.
pub const EXIT_REQUESTED: i32 = -1;

// ── export ──────────────────────────────────────────────────────────

/// Mark variables for export to child processes.
///
/// - `export` (no args) — list all exported variables.
/// - `export NAME` — mark NAME for export.
/// - `export NAME=VALUE` — set NAME to VALUE and mark for export.
fn builtin_export(args: &[String], env: &mut Environment) -> i32 {
    if args.is_empty() {
        // List all exported variables, sorted for determinism.
        let mut exported = env.exported_vars();
        exported.sort_by_key(|(k, _)| k.to_string());
        for (name, value) in &exported {
            println!("export {name}=\"{value}\"");
        }
        return 0;
    }

    for arg in args {
        if let Some(eq_pos) = arg.find('=') {
            let name = &arg[..eq_pos];
            let value = &arg[eq_pos + 1..];
            if !is_valid_name(name) {
                eprintln!("sh: export: `{arg}': not a valid identifier");
                return 1;
            }
            env.set(name, value, Some(true));
        } else {
            if !is_valid_name(arg) {
                eprintln!("sh: export: `{arg}': not a valid identifier");
                return 1;
            }
            env.export(arg);
        }
    }
    0
}

// ── unset ───────────────────────────────────────────────────────────

/// Remove shell variables.
///
/// - `unset NAME ...` — remove each named variable.
///
/// Per POSIX, `unset` with `-v` (default) unsets variables; `-f` would
/// unset functions (not yet supported).
fn builtin_unset(args: &[String], env: &mut Environment) -> i32 {
    let mut var_mode = true;
    let mut names_start = 0;

    // Parse options.
    for (i, arg) in args.iter().enumerate() {
        if arg == "-v" {
            var_mode = true;
            names_start = i + 1;
        } else if arg == "-f" {
            var_mode = false;
            names_start = i + 1;
        } else if arg.starts_with('-') {
            eprintln!("sh: unset: {arg}: invalid option");
            return 2;
        } else {
            names_start = i;
            break;
        }
    }

    if !var_mode {
        // Function unset not yet supported — silently succeed per
        // POSIX (unsetting a non-existent function is not an error).
        return 0;
    }

    for name in &args[names_start..] {
        if !is_valid_name(name) {
            eprintln!("sh: unset: `{name}': not a valid identifier");
            return 1;
        }
        env.unset(name);
    }
    0
}

// ── echo ────────────────────────────────────────────────────────────

/// Print arguments to stdout.
///
/// Per POSIX, `echo` does not process options. The XSI extension
/// recognizes `-n` (suppress trailing newline) which we implement
/// since it is ubiquitous.
fn builtin_echo(args: &[String]) -> i32 {
    let (suppress_newline, start) = if !args.is_empty() && args[0] == "-n" {
        (true, 1)
    } else {
        (false, 0)
    };

    let output: Vec<&str> = args[start..].iter().map(|s| s.as_str()).collect();
    let joined = output.join(" ");

    if suppress_newline {
        print!("{joined}");
    } else {
        println!("{joined}");
    }
    0
}

// ── test / [ ────────────────────────────────────────────────────────

/// `test EXPR` — evaluate a conditional expression and return 0 (true)
/// or 1 (false).
fn builtin_test(args: &[String]) -> i32 {
    eval_test_expr(args)
}

/// `[ EXPR ]` — same as `test`, but requires a closing `]`.
fn builtin_bracket(args: &[String]) -> i32 {
    if args.is_empty() || args.last().map(|s| s.as_str()) != Some("]") {
        eprintln!("sh: [: missing `]'");
        return 2;
    }
    // Strip the closing `]` and evaluate.
    eval_test_expr(&args[..args.len() - 1])
}

/// Evaluate a test expression and return 0 (true) or 1 (false).
///
/// Supports:
/// - Zero arguments: false (exit 1).
/// - One argument: true if the string is non-empty.
/// - Two arguments: unary operators (`-n`, `-z`, `-e`, `-f`, `-d`,
///   `-r`, `-w`, `-x`, `-s`, `!`).
/// - Three arguments: binary operators (`=`, `!=`, `-eq`, `-ne`,
///   `-lt`, `-gt`, `-le`, `-ge`).
/// - `! EXPR` — negate the expression.
fn eval_test_expr(args: &[String]) -> i32 {
    match args.len() {
        0 => 1, // No arguments: false.
        1 => {
            // Single argument: true if non-empty.
            if args[0].is_empty() {
                1
            } else {
                0
            }
        }
        2 => eval_test_unary(&args[0], &args[1]),
        3 => eval_test_binary_or_negation(args),
        _ => {
            // For longer expressions, check for leading `!`.
            if args[0] == "!" {
                let inner = eval_test_expr(&args[1..]);
                if inner == 0 {
                    1
                } else {
                    0
                }
            } else {
                eprintln!("sh: test: too many arguments");
                2
            }
        }
    }
}

/// Evaluate a two-argument test expression (unary operator + operand).
fn eval_test_unary(op: &str, operand: &str) -> i32 {
    let result = match op {
        "-n" => !operand.is_empty(),
        "-z" => operand.is_empty(),
        "!" => {
            // `! STRING` — true if STRING is empty.
            operand.is_empty()
        }
        // File tests — delegate to runtime.
        "-e" => file_exists(operand),
        "-f" => file_is_regular(operand),
        "-d" => file_is_directory(operand),
        "-r" => file_is_readable(operand),
        "-w" => file_is_writable(operand),
        "-x" => file_is_executable(operand),
        "-s" => file_has_size(operand),
        _ => {
            eprintln!("sh: test: {op}: unary operator expected");
            return 2;
        }
    };
    if result {
        0
    } else {
        1
    }
}

/// Evaluate a three-argument test expression — either a binary
/// comparison or `! UNARY_EXPR`.
fn eval_test_binary_or_negation(args: &[String]) -> i32 {
    if args[0] == "!" {
        // `! expr` where expr is a single argument.
        let inner = eval_test_expr(&args[1..]);
        return if inner == 0 { 1 } else { 0 };
    }

    // Binary: ARG1 OP ARG2
    let left = &args[0];
    let op = &args[1];
    let right = &args[2];

    match op.as_str() {
        "=" => {
            if left == right {
                0
            } else {
                1
            }
        }
        "!=" => {
            if left != right {
                0
            } else {
                1
            }
        }
        "-eq" | "-ne" | "-lt" | "-gt" | "-le" | "-ge" => {
            let cmp_fn: fn(i64, i64) -> bool = match op.as_str() {
                "-eq" => |a, b| a == b,
                "-ne" => |a, b| a != b,
                "-lt" => |a, b| a < b,
                "-gt" => |a, b| a > b,
                "-le" => |a, b| a <= b,
                "-ge" => |a, b| a >= b,
                _ => unreachable!(),
            };
            match int_cmp(left, right, cmp_fn) {
                Ok(true) => 0,
                Ok(false) => 1,
                Err(bad) => {
                    eprintln!("sh: test: {bad}: integer expression expected");
                    2
                }
            }
        }
        _ => {
            eprintln!("sh: test: {op}: binary operator expected");
            2
        }
    }
}

/// Parse two strings as integers and apply a comparison function.
/// Returns `Err` with the offending operand if either parse fails.
fn int_cmp(a: &str, b: &str, cmp: fn(i64, i64) -> bool) -> Result<bool, String> {
    let ia = a.parse::<i64>().map_err(|_| a.to_string())?;
    let ib = b.parse::<i64>().map_err(|_| b.to_string())?;
    Ok(cmp(ia, ib))
}

// File test implementations — runtime vs test stubs.

#[cfg(not(test))]
fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

#[cfg(not(test))]
fn file_is_regular(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

#[cfg(not(test))]
fn file_is_directory(path: &str) -> bool {
    std::path::Path::new(path).is_dir()
}

#[cfg(not(test))]
fn file_is_readable(_path: &str) -> bool {
    // Simplified: check if the file exists. A full implementation
    // would use access(2) with R_OK.
    std::path::Path::new(_path).exists()
}

#[cfg(not(test))]
fn file_is_writable(_path: &str) -> bool {
    std::path::Path::new(_path).exists()
}

#[cfg(not(test))]
fn file_is_executable(_path: &str) -> bool {
    std::path::Path::new(_path).exists()
}

#[cfg(not(test))]
fn file_has_size(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

// Test stubs for file tests — always return false (no filesystem in
// unit tests). The file-test logic is tested via integration tests.

#[cfg(test)]
fn file_exists(_path: &str) -> bool {
    false
}
#[cfg(test)]
fn file_is_regular(_path: &str) -> bool {
    false
}
#[cfg(test)]
fn file_is_directory(_path: &str) -> bool {
    false
}
#[cfg(test)]
fn file_is_readable(_path: &str) -> bool {
    false
}
#[cfg(test)]
fn file_is_writable(_path: &str) -> bool {
    false
}
#[cfg(test)]
fn file_is_executable(_path: &str) -> bool {
    false
}
#[cfg(test)]
fn file_has_size(_path: &str) -> bool {
    false
}

// ── read ────────────────────────────────────────────────────────────

/// Read a line from stdin and split it into variables.
///
/// - `read VAR` — read entire line into VAR.
/// - `read VAR1 VAR2 ...` — split line on IFS, assign each field to
///   the corresponding variable; the last variable gets the remainder.
/// - `read` (no args) — read into `$REPLY`.
fn builtin_read(args: &[String], env: &mut Environment) -> i32 {
    read_line_into(args, env)
}

#[cfg(not(test))]
fn read_line_into(args: &[String], env: &mut Environment) -> i32 {
    use std::io::BufRead;

    let mut line = String::new();
    let stdin = std::io::stdin();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => return 1, // EOF
        Ok(_) => {}
        Err(_) => return 1,
    }

    // Strip trailing newline.
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }

    assign_read_fields(&line, args, env);
    0
}

/// Test stub for read — reads from a pre-set `__TEST_READ_LINE`
/// variable in the environment.
#[cfg(test)]
fn read_line_into(args: &[String], env: &mut Environment) -> i32 {
    let line = match env.get("__TEST_READ_LINE") {
        Some(l) => l.to_string(),
        None => return 1,
    };
    assign_read_fields(&line, args, env);
    0
}

/// Split a line on IFS and assign fields to the given variable names.
fn assign_read_fields(line: &str, args: &[String], env: &mut Environment) {
    let var_names: Vec<&str> = if args.is_empty() {
        vec!["REPLY"]
    } else {
        args.iter().map(|s| s.as_str()).collect()
    };

    if var_names.len() == 1 {
        // Single variable gets the entire line.
        env.set(var_names[0], line, None);
        return;
    }

    let ifs = env
        .get("IFS")
        .map(|s| s.to_string())
        .unwrap_or_else(|| " \t\n".to_string());

    let fields = split_read_fields(line, &ifs);

    for (i, var) in var_names.iter().enumerate() {
        if i < var_names.len() - 1 {
            // Assign the i-th field, or empty if not enough fields.
            let val = fields.get(i).map(|s| s.as_str()).unwrap_or("");
            env.set(var, val, None);
        } else {
            // Last variable gets the remainder.
            if i < fields.len() {
                let sep = ifs
                    .chars()
                    .next()
                    .map(|c| c.to_string())
                    .unwrap_or_default();
                let remainder = fields[i..].join(&sep);
                env.set(var, &remainder, None);
            } else {
                env.set(var, "", None);
            }
        }
    }
}

/// Split a line for the `read` builtin. Similar to field_split but
/// without the full POSIX IFS semantics — just split on IFS chars,
/// coalescing whitespace.
fn split_read_fields(line: &str, ifs: &str) -> Vec<String> {
    if ifs.is_empty() {
        return vec![line.to_string()];
    }

    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_word = false;

    for c in line.chars() {
        if ifs.contains(c) {
            if in_word {
                fields.push(std::mem::take(&mut current));
                in_word = false;
            }
            // Skip consecutive IFS whitespace.
        } else {
            current.push(c);
            in_word = true;
        }
    }

    if in_word {
        fields.push(current);
    }

    fields
}

// ── exec ────────────────────────────────────────────────────────────

/// Replace the shell with a command, or manipulate the shell's own fds.
///
/// - `exec CMD ARGS...` — replace the shell process with CMD.
/// - `exec` (with redirections only) — redirections apply to the shell
///   itself (handled by the caller via the redirect list).
///
/// If CMD is given and execve fails, the shell exits with status 126/127.
fn builtin_exec(args: &[String], env: &mut Environment) -> i32 {
    if args.is_empty() {
        // No command — redirections are applied by the caller.
        return 0;
    }

    exec_replace(args, env)
}

#[cfg(not(test))]
fn exec_replace(args: &[String], env: &mut Environment) -> i32 {
    // Build argv as null-terminated C strings.
    let c_args: Vec<Vec<u8>> = args
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

    unsafe {
        execve(c_ptrs[0] as *const u8, c_ptrs.as_ptr(), c_env_ptrs.as_ptr());
    }

    // If we get here, execve failed.
    let errno = unsafe { *__errno_location() };
    eprintln!("sh: exec: {}: {}", args[0], errno_message(errno));
    if errno == 2 {
        127 // ENOENT
    } else {
        126
    }
}

#[cfg(test)]
fn exec_replace(args: &[String], _env: &mut Environment) -> i32 {
    // In tests, exec cannot actually replace the process.
    // Return 0 to indicate the command was recognized.
    let _ = args;
    0
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

// ── set ─────────────────────────────────────────────────────────────

/// Set shell options or positional parameters.
///
/// - `set` (no args) — list all variables.
/// - `set -- ARG ...` — set positional parameters.
/// - `set -e`, `set -x`, etc. — shell options (tracked in env).
///
/// Currently supports:
/// - `set --` to clear positional parameters.
/// - `set -- ARG ...` to set them.
/// - `set -e` / `set +e` — errexit (tracked as shell variable).
/// - `set -x` / `set +x` — xtrace (tracked as shell variable).
fn builtin_set(args: &[String], env: &mut Environment) -> i32 {
    if args.is_empty() {
        // List all variables, sorted.
        let mut vars: Vec<(&str, &str)> = env
            .vars
            .iter()
            .map(|(k, v)| (k.as_str(), v.value.as_str()))
            .collect();
        vars.sort_by_key(|(k, _)| k.to_string());
        for (name, value) in &vars {
            println!("{name}='{value}'");
        }
        return 0;
    }

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            // Everything after `--` becomes positional parameters.
            env.positional = args[i + 1..].iter().cloned().collect();
            return 0;
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            // Set options: -e, -x, etc.
            for ch in arg[1..].chars() {
                match ch {
                    'e' => env.set("__SH_OPT_ERREXIT", "1", None),
                    'x' => env.set("__SH_OPT_XTRACE", "1", None),
                    _ => {
                        eprintln!("sh: set: -{ch}: invalid option");
                        return 2;
                    }
                }
            }
        } else if arg.starts_with('+') && arg.len() > 1 {
            // Unset options: +e, +x, etc.
            for ch in arg[1..].chars() {
                match ch {
                    'e' => env.unset("__SH_OPT_ERREXIT"),
                    'x' => env.unset("__SH_OPT_XTRACE"),
                    _ => {
                        eprintln!("sh: set: +{ch}: invalid option");
                        return 2;
                    }
                }
            }
        } else {
            // Bare word — treat remaining args as positional params
            // (POSIX behavior when no `--` separator is given).
            env.positional = args[i..].iter().cloned().collect();
            return 0;
        }
        i += 1;
    }
    0
}

// ── . (dot/source) ──────────────────────────────────────────────────

/// Execute commands from a file in the current shell environment.
///
/// `. FILE [ARGS]` — read and execute commands from FILE. Positional
/// parameters are temporarily set to ARGS while the file executes
/// (restored afterwards).
fn builtin_dot(args: &[String], env: &mut Environment) -> i32 {
    if args.is_empty() {
        eprintln!("sh: .: filename argument required");
        return 2;
    }

    dot_source(&args[0], &args[1..], env)
}

#[cfg(not(test))]
fn dot_source(path: &str, extra_args: &[String], env: &mut Environment) -> i32 {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sh: .: {path}: {e}");
            return 1;
        }
    };

    // Save and set positional parameters if extra args given.
    let saved_positional = if !extra_args.is_empty() {
        let saved = env.positional.clone();
        env.positional = extra_args.to_vec();
        Some(saved)
    } else {
        None
    };

    // Parse and execute the file contents.
    // For now, just parse — the executor is not yet available, so we
    // validate syntax and return 0 if parseable.
    let result = match crate::parser::parse(&contents) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("sh: .: {path}: {e}");
            1
        }
    };

    // Restore positional parameters.
    if let Some(saved) = saved_positional {
        env.positional = saved;
    }

    result
}

#[cfg(test)]
fn dot_source(path: &str, extra_args: &[String], env: &mut Environment) -> i32 {
    // In tests, read file contents from a test variable.
    let contents = match env.get("__TEST_DOT_FILE") {
        Some(c) => c.to_string(),
        None => {
            eprintln!("sh: .: {path}: No such file or directory");
            return 1;
        }
    };

    let saved_positional = if !extra_args.is_empty() {
        let saved = env.positional.clone();
        env.positional = extra_args.to_vec();
        Some(saved)
    } else {
        None
    };

    // Validate parse.
    let result = match crate::parser::parse(&contents) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("sh: .: {path}: {e}");
            1
        }
    };

    if let Some(saved) = saved_positional {
        env.positional = saved;
    }

    result
}

// ── jobs ───────────────────────────────────────────────────────────

/// List all active jobs.
///
/// `jobs` — print one line per active job showing its number, status,
/// and the original command string.
fn builtin_jobs(_args: &[String], jobs: &mut JobTable) -> i32 {
    // Reap any children that have finished before listing.
    crate::job::reap_children(jobs);
    for job in jobs.active_jobs() {
        let marker = if Some(job.id) == jobs.current_job_id() {
            "+"
        } else {
            "-"
        };
        println!("[{}]{}\t{}\t{}", job.id, marker, job.status, job.command);
    }
    0
}

// ── fg ─────────────────────────────────────────────────────────────

/// Bring a background/stopped job to the foreground.
///
/// - `fg` (no args) — bring the current (most recent) job to fg.
/// - `fg %N` — bring job N to foreground.
/// - `fg N` — bring job N to foreground.
fn builtin_fg(args: &[String], env: &mut Environment, jobs: &mut JobTable) -> i32 {
    let job_id = if args.is_empty() {
        match jobs.current_job_id() {
            Some(id) => id,
            None => {
                eprintln!("sh: fg: no current job");
                return 1;
            }
        }
    } else {
        match parse_job_spec(&args[0]) {
            Some(id) => id,
            None => {
                eprintln!("sh: fg: {}: no such job", args[0]);
                return 1;
            }
        }
    };

    let (pgid, status, cmd) = match jobs.get(job_id) {
        Some(job) => (job.pgid, job.status, job.command.clone()),
        None => {
            eprintln!("sh: fg: %{job_id}: no such job");
            return 1;
        }
    };

    // Print the command being foregrounded.
    eprintln!("{cmd}");

    // If the job is stopped, send SIGCONT to its process group.
    if status == crate::job::JobStatus::Stopped {
        crate::job::send_signal(-pgid, crate::job::SIGCONT);
        if let Some(job) = jobs.get_mut(job_id) {
            job.status = crate::job::JobStatus::Running;
        }
    }

    // Wait for the job to finish or stop.
    fg_wait(pgid, job_id, env, jobs)
}

/// Wait for a foreground job to complete or stop.
#[cfg(not(test))]
fn fg_wait(pgid: i32, job_id: usize, env: &mut Environment, jobs: &mut JobTable) -> i32 {
    loop {
        let mut wstatus: i32 = 0;
        let pid = unsafe {
            crate::exec::wait4_raw(
                -pgid,
                &mut wstatus,
                crate::job::WUNTRACED,
                std::ptr::null(),
            )
        };
        if pid <= 0 {
            break;
        }
        if crate::job::wifstopped(wstatus) {
            // Job was stopped — update the job table.
            if let Some(job) = jobs.get_mut(job_id) {
                job.status = crate::job::JobStatus::Stopped;
            }
            let sig = crate::job::wstopsig(wstatus);
            let exit_code = 128 + sig;
            env.last_status = exit_code;
            eprintln!();
            if let Some(job) = jobs.get(job_id) {
                eprintln!("[{}]+\tStopped\t\t{}", job.id, job.command);
            }
            return exit_code;
        } else {
            // Job exited or was signaled — remove from table.
            let exit_code = if crate::job::wifsignaled(wstatus) {
                128 + crate::job::wtermsig(wstatus)
            } else {
                crate::job::wexitstatus(wstatus)
            };
            if let Some(job) = jobs.get_mut(job_id) {
                job.status = crate::job::JobStatus::Done(exit_code);
            }
            env.last_status = exit_code;
            return exit_code;
        }
    }
    env.last_status
}

#[cfg(test)]
fn fg_wait(_pgid: i32, _job_id: usize, env: &mut Environment, _jobs: &mut JobTable) -> i32 {
    env.last_status
}

// ── bg ─────────────────────────────────────────────────────────────

/// Resume a stopped job in the background.
///
/// - `bg` (no args) — resume the current (most recent) stopped job.
/// - `bg %N` — resume job N in the background.
fn builtin_bg(args: &[String], env: &mut Environment, jobs: &mut JobTable) -> i32 {
    let _ = env;
    let job_id = if args.is_empty() {
        // Find the most recent stopped job.
        match jobs
            .active_jobs()
            .iter()
            .rev()
            .find(|j| j.status == crate::job::JobStatus::Stopped)
            .map(|j| j.id)
        {
            Some(id) => id,
            None => {
                eprintln!("sh: bg: no current job");
                return 1;
            }
        }
    } else {
        match parse_job_spec(&args[0]) {
            Some(id) => id,
            None => {
                eprintln!("sh: bg: {}: no such job", args[0]);
                return 1;
            }
        }
    };

    let (pgid, status, cmd) = match jobs.get(job_id) {
        Some(job) => (job.pgid, job.status, job.command.clone()),
        None => {
            eprintln!("sh: bg: %{job_id}: no such job");
            return 1;
        }
    };

    if status != crate::job::JobStatus::Stopped {
        eprintln!("sh: bg: job {job_id} already running");
        return 1;
    }

    // Send SIGCONT and mark as running.
    crate::job::send_signal(-pgid, crate::job::SIGCONT);
    if let Some(job) = jobs.get_mut(job_id) {
        job.status = crate::job::JobStatus::Running;
    }
    eprintln!("[{job_id}]+ {cmd} &");
    0
}

// ── Job spec parsing ──────────────────────────────────────────────

/// Parse a job specification like `%1` or `1` into a job ID.
pub fn parse_job_spec(spec: &str) -> Option<usize> {
    let num_str = if let Some(stripped) = spec.strip_prefix('%') {
        stripped
    } else {
        spec
    };
    let id = num_str.parse::<usize>().ok()?;
    if id == 0 {
        None
    } else {
        Some(id)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Validate that a string is a valid POSIX shell variable name.
pub fn is_valid_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = name.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

// ── Extern C declarations ──────────────────────────────────────────

#[cfg(not(test))]
extern "C" {
    fn chdir(path: *const u8) -> i32;
    fn getcwd(buf: *mut u8, size: usize) -> *mut u8;
    fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32;
    fn __errno_location() -> *mut i32;
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expand::Environment;

    fn env() -> Environment {
        Environment::new()
    }

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // ── is_builtin ──────────────────────────────────────────────────

    #[test]
    fn is_builtin_recognizes_all() {
        for name in &[
            "cd", "exit", "export", "unset", "echo", "test", "[", "read", "exec", "set", ".",
        ] {
            assert!(is_builtin(name), "expected {name} to be a builtin");
        }
    }

    #[test]
    fn is_builtin_rejects_external() {
        assert!(!is_builtin("ls"));
        assert!(!is_builtin("grep"));
        assert!(!is_builtin(""));
    }

    // ── is_valid_name ───────────────────────────────────────────────

    #[test]
    fn valid_names() {
        assert!(is_valid_name("FOO"));
        assert!(is_valid_name("_bar"));
        assert!(is_valid_name("a123"));
        assert!(is_valid_name("__"));
    }

    #[test]
    fn invalid_names() {
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("123"));
        assert!(!is_valid_name("-x"));
        assert!(!is_valid_name("foo-bar"));
        assert!(!is_valid_name("a.b"));
    }

    // ── cd ──────────────────────────────────────────────────────────

    #[test]
    fn cd_to_home() {
        let mut e = env();
        e.set("HOME", "/home/user", None);
        let status = builtin_cd(&args(&[]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("PWD"), Some("/home/user"));
    }

    #[test]
    fn cd_no_home() {
        let mut e = env();
        let status = builtin_cd(&args(&[]), &mut e);
        assert_eq!(status, 1);
    }

    #[test]
    fn cd_explicit_dir() {
        let mut e = env();
        e.set("PWD", "/old", None);
        let status = builtin_cd(&args(&["/new"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("PWD"), Some("/new"));
        assert_eq!(e.get("OLDPWD"), Some("/old"));
    }

    #[test]
    fn cd_dash_goes_to_oldpwd() {
        let mut e = env();
        e.set("OLDPWD", "/prev", None);
        e.set("PWD", "/current", None);
        let status = builtin_cd(&args(&["-"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("PWD"), Some("/prev"));
        assert_eq!(e.get("OLDPWD"), Some("/current"));
    }

    #[test]
    fn cd_dash_no_oldpwd() {
        let mut e = env();
        let status = builtin_cd(&args(&["-"]), &mut e);
        assert_eq!(status, 1);
    }

    // ── exit ────────────────────────────────────────────────────────

    #[test]
    fn exit_no_args_uses_last_status() {
        let mut e = env();
        e.last_status = 42;
        let status = builtin_exit(&args(&[]), &mut e);
        assert_eq!(status, EXIT_REQUESTED);
        assert_eq!(e.last_status, 42);
    }

    #[test]
    fn exit_with_code() {
        let mut e = env();
        let status = builtin_exit(&args(&["3"]), &mut e);
        assert_eq!(status, EXIT_REQUESTED);
        assert_eq!(e.last_status, 3);
    }

    #[test]
    fn exit_masks_to_byte() {
        let mut e = env();
        let status = builtin_exit(&args(&["256"]), &mut e);
        assert_eq!(status, EXIT_REQUESTED);
        assert_eq!(e.last_status, 0); // 256 & 0xFF == 0
    }

    #[test]
    fn exit_non_numeric() {
        let mut e = env();
        let status = builtin_exit(&args(&["abc"]), &mut e);
        assert_eq!(status, EXIT_REQUESTED);
        assert_eq!(e.last_status, 2);
    }

    // ── export ──────────────────────────────────────────────────────

    #[test]
    fn export_name_only() {
        let mut e = env();
        e.set("FOO", "bar", None);
        let status = builtin_export(&args(&["FOO"]), &mut e);
        assert_eq!(status, 0);
        assert!(e.vars.get("FOO").unwrap().exported);
    }

    #[test]
    fn export_with_value() {
        let mut e = env();
        let status = builtin_export(&args(&["FOO=bar"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("FOO"), Some("bar"));
        assert!(e.vars.get("FOO").unwrap().exported);
    }

    #[test]
    fn export_unset_var_creates_empty() {
        let mut e = env();
        let status = builtin_export(&args(&["NEWVAR"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("NEWVAR"), Some(""));
        assert!(e.vars.get("NEWVAR").unwrap().exported);
    }

    #[test]
    fn export_invalid_name() {
        let mut e = env();
        let status = builtin_export(&args(&["123"]), &mut e);
        assert_eq!(status, 1);
    }

    #[test]
    fn export_invalid_assignment() {
        let mut e = env();
        let status = builtin_export(&args(&["1a=b"]), &mut e);
        assert_eq!(status, 1);
    }

    #[test]
    fn export_empty_value() {
        let mut e = env();
        let status = builtin_export(&args(&["FOO="]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("FOO"), Some(""));
        assert!(e.vars.get("FOO").unwrap().exported);
    }

    // ── unset ───────────────────────────────────────────────────────

    #[test]
    fn unset_removes_variable() {
        let mut e = env();
        e.set("FOO", "bar", None);
        let status = builtin_unset(&args(&["FOO"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("FOO"), None);
    }

    #[test]
    fn unset_multiple() {
        let mut e = env();
        e.set("A", "1", None);
        e.set("B", "2", None);
        let status = builtin_unset(&args(&["A", "B"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("A"), None);
        assert_eq!(e.get("B"), None);
    }

    #[test]
    fn unset_nonexistent_is_ok() {
        let mut e = env();
        let status = builtin_unset(&args(&["NOSUCH"]), &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn unset_with_v_flag() {
        let mut e = env();
        e.set("FOO", "bar", None);
        let status = builtin_unset(&args(&["-v", "FOO"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("FOO"), None);
    }

    #[test]
    fn unset_with_f_flag_is_noop() {
        let mut e = env();
        let status = builtin_unset(&args(&["-f", "myfunc"]), &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn unset_invalid_name() {
        let mut e = env();
        let status = builtin_unset(&args(&["123"]), &mut e);
        assert_eq!(status, 1);
    }

    // ── echo ────────────────────────────────────────────────────────

    #[test]
    fn echo_basic() {
        // Just verify it returns 0 — stdout capture requires more
        // infrastructure.
        let status = builtin_echo(&args(&["hello", "world"]));
        assert_eq!(status, 0);
    }

    #[test]
    fn echo_no_args() {
        let status = builtin_echo(&args(&[]));
        assert_eq!(status, 0);
    }

    #[test]
    fn echo_n_flag() {
        let status = builtin_echo(&args(&["-n", "test"]));
        assert_eq!(status, 0);
    }

    // ── test / [ ────────────────────────────────────────────────────

    #[test]
    fn test_no_args_false() {
        assert_eq!(builtin_test(&args(&[])), 1);
    }

    #[test]
    fn test_single_nonempty_true() {
        assert_eq!(builtin_test(&args(&["hello"])), 0);
    }

    #[test]
    fn test_single_empty_false() {
        assert_eq!(builtin_test(&args(&[""])), 1);
    }

    #[test]
    fn test_n_nonempty() {
        assert_eq!(builtin_test(&args(&["-n", "hello"])), 0);
    }

    #[test]
    fn test_n_empty() {
        assert_eq!(builtin_test(&args(&["-n", ""])), 1);
    }

    #[test]
    fn test_z_empty() {
        assert_eq!(builtin_test(&args(&["-z", ""])), 0);
    }

    #[test]
    fn test_z_nonempty() {
        assert_eq!(builtin_test(&args(&["-z", "hello"])), 1);
    }

    #[test]
    fn test_string_eq() {
        assert_eq!(builtin_test(&args(&["abc", "=", "abc"])), 0);
    }

    #[test]
    fn test_string_neq() {
        assert_eq!(builtin_test(&args(&["abc", "!=", "def"])), 0);
    }

    #[test]
    fn test_string_eq_fail() {
        assert_eq!(builtin_test(&args(&["abc", "=", "def"])), 1);
    }

    #[test]
    fn test_int_eq() {
        assert_eq!(builtin_test(&args(&["42", "-eq", "42"])), 0);
    }

    #[test]
    fn test_int_ne() {
        assert_eq!(builtin_test(&args(&["1", "-ne", "2"])), 0);
    }

    #[test]
    fn test_int_lt() {
        assert_eq!(builtin_test(&args(&["1", "-lt", "2"])), 0);
        assert_eq!(builtin_test(&args(&["2", "-lt", "1"])), 1);
    }

    #[test]
    fn test_int_gt() {
        assert_eq!(builtin_test(&args(&["2", "-gt", "1"])), 0);
        assert_eq!(builtin_test(&args(&["1", "-gt", "2"])), 1);
    }

    #[test]
    fn test_int_le() {
        assert_eq!(builtin_test(&args(&["1", "-le", "1"])), 0);
        assert_eq!(builtin_test(&args(&["1", "-le", "2"])), 0);
        assert_eq!(builtin_test(&args(&["2", "-le", "1"])), 1);
    }

    #[test]
    fn test_int_ge() {
        assert_eq!(builtin_test(&args(&["2", "-ge", "2"])), 0);
        assert_eq!(builtin_test(&args(&["2", "-ge", "1"])), 0);
        assert_eq!(builtin_test(&args(&["1", "-ge", "2"])), 1);
    }

    #[test]
    fn test_negation() {
        // `! -n ""` → ! false → true
        assert_eq!(builtin_test(&args(&["!", "-n", ""])), 0);
        // `! -n "hello"` → ! true → false
        assert_eq!(builtin_test(&args(&["!", "-n", "hello"])), 1);
    }

    #[test]
    fn test_unary_negation() {
        // `! hello` → hello is non-empty, so false
        assert_eq!(builtin_test(&args(&["!", "hello"])), 1);
        // `! ""` → empty, so true
        assert_eq!(builtin_test(&args(&["!", ""])), 0);
    }

    #[test]
    fn bracket_basic() {
        assert_eq!(builtin_bracket(&args(&["hello", "]"])), 0);
    }

    #[test]
    fn bracket_missing_close() {
        assert_eq!(builtin_bracket(&args(&["hello"])), 2);
    }

    #[test]
    fn bracket_empty() {
        assert_eq!(builtin_bracket(&args(&[])), 2);
    }

    #[test]
    fn bracket_comparison() {
        assert_eq!(builtin_bracket(&args(&["1", "-eq", "1", "]"])), 0);
        assert_eq!(builtin_bracket(&args(&["1", "-eq", "2", "]"])), 1);
    }

    // ── read ────────────────────────────────────────────────────────

    #[test]
    fn read_single_var() {
        let mut e = env();
        e.set("__TEST_READ_LINE", "hello world", None);
        let status = builtin_read(&args(&["VAR"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("VAR"), Some("hello world"));
    }

    #[test]
    fn read_multiple_vars() {
        let mut e = env();
        e.set("__TEST_READ_LINE", "one two three four", None);
        let status = builtin_read(&args(&["A", "B", "C"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("A"), Some("one"));
        assert_eq!(e.get("B"), Some("two"));
        assert_eq!(e.get("C"), Some("three four"));
    }

    #[test]
    fn read_no_var_uses_reply() {
        let mut e = env();
        e.set("__TEST_READ_LINE", "hello", None);
        let status = builtin_read(&args(&[]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("REPLY"), Some("hello"));
    }

    #[test]
    fn read_eof_returns_1() {
        let mut e = env();
        // No __TEST_READ_LINE set → simulates EOF.
        let status = builtin_read(&args(&["VAR"]), &mut e);
        assert_eq!(status, 1);
    }

    #[test]
    fn read_more_vars_than_fields() {
        let mut e = env();
        e.set("__TEST_READ_LINE", "one", None);
        let status = builtin_read(&args(&["A", "B", "C"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("A"), Some("one"));
        assert_eq!(e.get("B"), Some(""));
        assert_eq!(e.get("C"), Some(""));
    }

    // ── split_read_fields ───────────────────────────────────────────

    #[test]
    fn split_read_fields_basic() {
        let fields = split_read_fields("hello world", " \t\n");
        assert_eq!(fields, vec!["hello", "world"]);
    }

    #[test]
    fn split_read_fields_extra_spaces() {
        let fields = split_read_fields("  a   b   c  ", " \t\n");
        assert_eq!(fields, vec!["a", "b", "c"]);
    }

    #[test]
    fn split_read_fields_empty_ifs() {
        let fields = split_read_fields("hello world", "");
        assert_eq!(fields, vec!["hello world"]);
    }

    #[test]
    fn split_read_fields_custom_ifs() {
        let fields = split_read_fields("a:b:c", ":");
        assert_eq!(fields, vec!["a", "b", "c"]);
    }

    // ── exec ────────────────────────────────────────────────────────

    #[test]
    fn exec_no_args() {
        let mut e = env();
        let status = builtin_exec(&args(&[]), &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn exec_with_command() {
        let mut e = env();
        let status = builtin_exec(&args(&["/bin/ls"]), &mut e);
        assert_eq!(status, 0); // test stub returns 0
    }

    // ── set ─────────────────────────────────────────────────────────

    #[test]
    fn set_positional_params() {
        let mut e = env();
        let status = builtin_set(&args(&["--", "a", "b", "c"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.positional, vec!["a", "b", "c"]);
    }

    #[test]
    fn set_clear_positional() {
        let mut e = env();
        e.positional = vec!["old".to_string()];
        let status = builtin_set(&args(&["--"]), &mut e);
        assert_eq!(status, 0);
        assert!(e.positional.is_empty());
    }

    #[test]
    fn set_enable_errexit() {
        let mut e = env();
        let status = builtin_set(&args(&["-e"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("__SH_OPT_ERREXIT"), Some("1"));
    }

    #[test]
    fn set_disable_errexit() {
        let mut e = env();
        e.set("__SH_OPT_ERREXIT", "1", None);
        let status = builtin_set(&args(&["+e"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("__SH_OPT_ERREXIT"), None);
    }

    #[test]
    fn set_enable_xtrace() {
        let mut e = env();
        let status = builtin_set(&args(&["-x"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.get("__SH_OPT_XTRACE"), Some("1"));
    }

    #[test]
    fn set_invalid_option() {
        let mut e = env();
        let status = builtin_set(&args(&["-Z"]), &mut e);
        assert_eq!(status, 2);
    }

    #[test]
    fn set_no_args_lists_vars() {
        let mut e = env();
        e.set("FOO", "bar", None);
        // Just check it returns 0.
        let status = builtin_set(&args(&[]), &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn set_bare_words_as_positional() {
        let mut e = env();
        let status = builtin_set(&args(&["x", "y", "z"]), &mut e);
        assert_eq!(status, 0);
        assert_eq!(e.positional, vec!["x", "y", "z"]);
    }

    // ── . (dot/source) ──────────────────────────────────────────────

    #[test]
    fn dot_no_args() {
        let mut e = env();
        let status = builtin_dot(&args(&[]), &mut e);
        assert_eq!(status, 2);
    }

    #[test]
    fn dot_file_not_found() {
        let mut e = env();
        let status = builtin_dot(&args(&["nosuchfile"]), &mut e);
        assert_eq!(status, 1);
    }

    #[test]
    fn dot_valid_file() {
        let mut e = env();
        e.set("__TEST_DOT_FILE", "echo hello\n", None);
        let status = builtin_dot(&args(&["test.sh"]), &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn dot_syntax_error() {
        let mut e = env();
        e.set("__TEST_DOT_FILE", "echo 'unterminated", None);
        let status = builtin_dot(&args(&["bad.sh"]), &mut e);
        assert_eq!(status, 1);
    }

    #[test]
    fn dot_with_extra_args_sets_positional() {
        let mut e = env();
        e.set("__TEST_DOT_FILE", "echo hello\n", None);
        e.positional = vec!["original".to_string()];
        let status = builtin_dot(&args(&["test.sh", "arg1", "arg2"]), &mut e);
        assert_eq!(status, 0);
        // Positional parameters should be restored.
        assert_eq!(e.positional, vec!["original"]);
    }

    // ── run_builtin dispatch ────────────────────────────────────────

    #[test]
    fn dispatch_echo() {
        let mut e = env();
        let status = run_builtin("echo", &args(&["hi"]), &mut e);
        assert_eq!(status, 0);
    }

    #[test]
    fn dispatch_unknown() {
        let mut e = env();
        let status = run_builtin("nosuch", &args(&[]), &mut e);
        assert_eq!(status, 1);
    }

    // ── is_builtin recognizes new builtins ─────────────────────────

    #[test]
    fn is_builtin_recognizes_job_builtins() {
        assert!(is_builtin("jobs"));
        assert!(is_builtin("fg"));
        assert!(is_builtin("bg"));
    }

    #[test]
    fn is_job_builtin_identifies_job_cmds() {
        assert!(is_job_builtin("jobs"));
        assert!(is_job_builtin("fg"));
        assert!(is_job_builtin("bg"));
        assert!(!is_job_builtin("echo"));
        assert!(!is_job_builtin("cd"));
    }

    // ── parse_job_spec ─────────────────────────────────────────────

    #[test]
    fn parse_job_spec_percent() {
        assert_eq!(parse_job_spec("%1"), Some(1));
        assert_eq!(parse_job_spec("%42"), Some(42));
    }

    #[test]
    fn parse_job_spec_bare_number() {
        assert_eq!(parse_job_spec("1"), Some(1));
        assert_eq!(parse_job_spec("99"), Some(99));
    }

    #[test]
    fn parse_job_spec_invalid() {
        assert_eq!(parse_job_spec("abc"), None);
        assert_eq!(parse_job_spec("%abc"), None);
        assert_eq!(parse_job_spec(""), None);
        assert_eq!(parse_job_spec("%0"), None);
        assert_eq!(parse_job_spec("0"), None);
    }

    // ── jobs builtin ───────────────────────────────────────────────

    #[test]
    fn jobs_empty_table() {
        let mut jobs = JobTable::new();
        let status = builtin_jobs(&args(&[]), &mut jobs);
        assert_eq!(status, 0);
    }

    #[test]
    fn jobs_with_entries() {
        let mut jobs = JobTable::new();
        jobs.add(100, 100, "sleep 10 &".to_string());
        jobs.add(200, 200, "cat &".to_string());
        let status = builtin_jobs(&args(&[]), &mut jobs);
        assert_eq!(status, 0);
    }

    // ── fg builtin ─────────────────────────────────────────────────

    #[test]
    fn fg_no_current_job() {
        let mut e = env();
        let mut jobs = JobTable::new();
        let status = builtin_fg(&args(&[]), &mut e, &mut jobs);
        assert_eq!(status, 1);
    }

    #[test]
    fn fg_nonexistent_job() {
        let mut e = env();
        let mut jobs = JobTable::new();
        let status = builtin_fg(&args(&["%99"]), &mut e, &mut jobs);
        assert_eq!(status, 1);
    }

    // ── bg builtin ─────────────────────────────────────────────────

    #[test]
    fn bg_no_stopped_job() {
        let mut e = env();
        let mut jobs = JobTable::new();
        let status = builtin_bg(&args(&[]), &mut e, &mut jobs);
        assert_eq!(status, 1);
    }

    #[test]
    fn bg_running_job_already() {
        let mut e = env();
        let mut jobs = JobTable::new();
        jobs.add(100, 100, "cmd &".to_string());
        let status = builtin_bg(&args(&["%1"]), &mut e, &mut jobs);
        assert_eq!(status, 1); // already running
    }

    #[test]
    fn bg_stopped_job() {
        let mut e = env();
        let mut jobs = JobTable::new();
        jobs.add(100, 100, "cmd".to_string());
        jobs.get_mut(1).unwrap().status = crate::job::JobStatus::Stopped;
        let status = builtin_bg(&args(&["%1"]), &mut e, &mut jobs);
        assert_eq!(status, 0);
        assert_eq!(
            jobs.get(1).unwrap().status,
            crate::job::JobStatus::Running
        );
    }

    // ── run_job_builtin dispatch ───────────────────────────────────

    #[test]
    fn dispatch_job_builtins() {
        let mut e = env();
        let mut jobs = JobTable::new();
        // jobs with empty table should succeed
        let status = run_job_builtin("jobs", &args(&[]), &mut e, &mut jobs);
        assert_eq!(status, 0);
    }
}
