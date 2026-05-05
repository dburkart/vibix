//! Runtime application of I/O redirections per POSIX.1-2024 section 2.7.
//!
//! This module takes the parsed [`Redirect`] AST nodes from the parser
//! and applies them to the process's file descriptor table using the
//! `open`, `close`, and `dup2` syscalls.
//!
//! ## Design
//!
//! Redirections are applied left-to-right (per POSIX) after `fork()` but
//! before `exec()`. Each redirection either opens a file, duplicates a
//! file descriptor, or closes one.
//!
//! The [`apply_redirects`] function processes a slice of [`Redirect`]
//! nodes and returns a [`SavedFds`] that can restore the original fd
//! state when the command completes (used for builtins that run in the
//! shell process itself).
//!
//! ## Here-documents
//!
//! Here-documents (`<<DELIM` ... `DELIM`) are materialized into a
//! temporary pipe: the document body is written to the write end, which
//! is then closed, and the read end is `dup2`'d onto the target fd
//! (default: stdin). Tab stripping (`<<-`) removes leading tabs from
//! each line of the body.

use crate::parser::{Redirect, RedirectOp};

/// Raw file descriptor type (i32 on all POSIX platforms).
pub type RawFd = i32;

// ── POSIX open(2) flag constants (Linux x86_64 ABI) ──────────────────

/// Open for reading only.
pub const O_RDONLY: i32 = 0;
/// Open for writing only.
pub const O_WRONLY: i32 = 1;
/// Open for reading and writing.
pub const O_RDWR: i32 = 2;
/// Create the file if it does not exist.
pub const O_CREAT: i32 = 0o100;
/// Truncate the file to zero length.
pub const O_TRUNC: i32 = 0o1000;
/// Append mode — writes go to end of file.
pub const O_APPEND: i32 = 0o2000;

// ── fcntl(2) constants ───────────────────────────────────────────────

/// Get file descriptor flags.
const F_GETFD: i32 = 1;
/// Set file descriptor flags.
const F_SETFD: i32 = 2;
/// Close-on-exec flag.
const FD_CLOEXEC: i32 = 1;

// ── Error type ───────────────────────────────────────────────────────

/// An error encountered while applying a redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectError {
    /// Failed to open a file.
    OpenFailed { path: String, errno: i32 },
    /// `dup2` syscall failed.
    DupFailed { src: RawFd, dst: RawFd, errno: i32 },
    /// `close` syscall failed.
    CloseFailed { fd: RawFd, errno: i32 },
    /// `pipe` syscall failed.
    PipeFailed { errno: i32 },
    /// `write` syscall failed (here-doc body).
    WriteFailed { errno: i32 },
    /// Invalid fd number in a dup target (e.g. `>&abc`).
    InvalidFdTarget { target: String },
    /// Attempted to dup from an fd that is not open.
    BadFdNumber { fd: RawFd },
}

impl std::fmt::Display for RedirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedirectError::OpenFailed { path, errno } => {
                write!(f, "cannot open {path}: errno {errno}")
            }
            RedirectError::DupFailed { src, dst, errno } => {
                write!(f, "dup2({src}, {dst}) failed: errno {errno}")
            }
            RedirectError::CloseFailed { fd, errno } => {
                write!(f, "close({fd}) failed: errno {errno}")
            }
            RedirectError::PipeFailed { errno } => {
                write!(f, "pipe() failed: errno {errno}")
            }
            RedirectError::WriteFailed { errno } => {
                write!(f, "write to pipe failed: errno {errno}")
            }
            RedirectError::InvalidFdTarget { target } => {
                write!(f, "invalid fd target: {target}")
            }
            RedirectError::BadFdNumber { fd } => {
                write!(f, "bad file descriptor: {fd}")
            }
        }
    }
}

// ── Saved file descriptor state ──────────────────────────────────────

/// A saved copy of file descriptors that were overwritten by
/// redirections. Call [`SavedFds::restore`] to undo the redirections
/// (for shell builtins).
#[derive(Debug, Default)]
pub struct SavedFds {
    /// `(saved_copy_fd, original_fd)` — `saved_copy_fd` is a dup of the
    /// original fd made before the redirect overwrote it.
    saves: Vec<(RawFd, RawFd)>,
}

impl SavedFds {
    fn new() -> Self {
        Self { saves: Vec::new() }
    }

    /// Restore all saved file descriptors in reverse order and close the
    /// temporary copies.
    #[cfg(not(test))]
    pub fn restore(self) -> Result<(), RedirectError> {
        for (saved_copy, original_fd) in self.saves.into_iter().rev() {
            let ret = unsafe { dup2(saved_copy, original_fd) };
            if ret < 0 {
                return Err(RedirectError::DupFailed {
                    src: saved_copy,
                    dst: original_fd,
                    errno: get_errno(),
                });
            }
            unsafe {
                close(saved_copy);
            }
        }
        Ok(())
    }

    /// Test stub for restore — does nothing (no real fds in unit tests).
    #[cfg(test)]
    pub fn restore(self) -> Result<(), RedirectError> {
        Ok(())
    }
}

// ── Extern C declarations for POSIX syscalls ─────────────────────────
//
// These are provided by vibix_libc (linked into the binary via std).
// We declare them here rather than depending on the `libc` crate
// directly, since the shell uses `restricted_std` and gets its C
// symbols from the vibix toolchain.

extern "C" {
    fn open(pathname: *const u8, flags: i32, mode: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn pipe(pipefd: *mut i32) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn __errno_location() -> *mut i32;
}

/// Retrieve the current errno value.
#[cfg(not(test))]
fn get_errno() -> i32 {
    unsafe { *__errno_location() }
}

// ── Pure logic helpers (testable on the host) ────────────────────────

/// Resolve the default fd for a redirect operator when no explicit fd
/// number was given.
pub fn default_fd(op: RedirectOp) -> RawFd {
    match op {
        RedirectOp::Input | RedirectOp::DupInput | RedirectOp::ReadWrite | RedirectOp::HereDoc => {
            0 // stdin
        }
        RedirectOp::Output | RedirectOp::Append | RedirectOp::DupOutput => 1, // stdout
    }
}

/// Compute the open flags for a file-based redirection.
pub fn open_flags(op: RedirectOp) -> i32 {
    match op {
        RedirectOp::Input => O_RDONLY,
        RedirectOp::Output => O_WRONLY | O_CREAT | O_TRUNC,
        RedirectOp::Append => O_WRONLY | O_CREAT | O_APPEND,
        RedirectOp::ReadWrite => O_RDWR | O_CREAT,
        _ => 0, // DupInput, DupOutput, HereDoc don't open files
    }
}

/// The target of a dup redirection (`>&N` or `>&-`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DupTarget {
    /// Duplicate from the given fd number.
    Fd(RawFd),
    /// Close the fd.
    Close,
}

/// Parse a dup target string into either a file descriptor number or a
/// close indicator (`-`).
pub fn parse_dup_target(target: &str) -> Result<DupTarget, RedirectError> {
    if target == "-" {
        Ok(DupTarget::Close)
    } else {
        target
            .parse::<RawFd>()
            .map(DupTarget::Fd)
            .map_err(|_| RedirectError::InvalidFdTarget {
                target: target.to_string(),
            })
    }
}

/// Resolve the effective fd for a redirect, applying the default if no
/// explicit fd was given.
pub fn resolve_fd(redir: &Redirect) -> RawFd {
    redir
        .fd
        .map(|n| n as RawFd)
        .unwrap_or_else(|| default_fd(redir.op))
}

/// Strip leading tabs from each line of a here-document body (for the
/// `<<-` variant). Preserves a trailing newline if the input has one.
pub fn strip_heredoc_tabs(body: &str) -> String {
    let mut result: String = body
        .lines()
        .map(|line| line.trim_start_matches('\t'))
        .collect::<Vec<_>>()
        .join("\n");
    if body.ends_with('\n') {
        result.push('\n');
    }
    result
}

// ── Core redirect application (runtime, not compiled for tests) ──────

/// Apply a list of redirections left-to-right, returning saved state so
/// they can be undone later (for builtins). For external commands that
/// `exec` after redirecting, the saved state can be dropped.
///
/// This is the main entry point for the redirect runtime.
#[cfg(not(test))]
pub fn apply_redirects(redirects: &[Redirect]) -> Result<SavedFds, RedirectError> {
    let mut saved = SavedFds::new();

    for redir in redirects {
        let fd = resolve_fd(redir);

        match redir.op {
            RedirectOp::Input
            | RedirectOp::Output
            | RedirectOp::Append
            | RedirectOp::ReadWrite => {
                // Save the current fd before overwriting.
                save_fd(fd, &mut saved)?;

                let flags = open_flags(redir.op);
                let mode: u32 = 0o666; // umask will reduce this

                // Build a null-terminated path.
                let mut path_buf = redir.target.as_bytes().to_vec();
                path_buf.push(0);

                let opened = unsafe { open(path_buf.as_ptr(), flags, mode) };
                if opened < 0 {
                    return Err(RedirectError::OpenFailed {
                        path: redir.target.clone(),
                        errno: get_errno(),
                    });
                }
                if opened != fd {
                    let ret = unsafe { dup2(opened, fd) };
                    if ret < 0 {
                        let e = get_errno();
                        unsafe {
                            close(opened);
                        }
                        return Err(RedirectError::DupFailed {
                            src: opened,
                            dst: fd,
                            errno: e,
                        });
                    }
                    unsafe {
                        close(opened);
                    }
                }
            }
            RedirectOp::DupOutput | RedirectOp::DupInput => {
                let target = parse_dup_target(&redir.target)?;
                save_fd(fd, &mut saved)?;
                match target {
                    DupTarget::Fd(src_fd) => {
                        let ret = unsafe { dup2(src_fd, fd) };
                        if ret < 0 {
                            return Err(RedirectError::DupFailed {
                                src: src_fd,
                                dst: fd,
                                errno: get_errno(),
                            });
                        }
                    }
                    DupTarget::Close => {
                        let ret = unsafe { close(fd) };
                        if ret < 0 {
                            return Err(RedirectError::CloseFailed {
                                fd,
                                errno: get_errno(),
                            });
                        }
                    }
                }
            }
            RedirectOp::HereDoc => {
                save_fd(fd, &mut saved)?;
                apply_heredoc(fd, &redir.target)?;
            }
        }
    }

    Ok(saved)
}

/// Apply a here-document: write the body into a pipe and dup the read
/// end onto `target_fd`.
///
/// The `target` field for a here-doc redirect contains the document body
/// (the parser is responsible for collecting lines between the delimiter
/// markers and storing the body in `Redirect::target`).
#[cfg(not(test))]
fn apply_heredoc(target_fd: RawFd, body: &str) -> Result<(), RedirectError> {
    let mut pipe_fds: [RawFd; 2] = [0; 2];
    let ret = unsafe { pipe(pipe_fds.as_mut_ptr()) };
    if ret < 0 {
        return Err(RedirectError::PipeFailed {
            errno: get_errno(),
        });
    }
    let read_end = pipe_fds[0];
    let write_end = pipe_fds[1];

    // Write the body to the pipe.
    let bytes = body.as_bytes();
    let mut written = 0;
    while written < bytes.len() {
        let n = unsafe { write(write_end, bytes[written..].as_ptr(), bytes.len() - written) };
        if n < 0 {
            let e = get_errno();
            unsafe {
                close(read_end);
                close(write_end);
            }
            return Err(RedirectError::WriteFailed { errno: e });
        }
        written += n as usize;
    }
    unsafe {
        close(write_end);
    }

    // Dup the read end onto the target fd.
    if read_end != target_fd {
        let ret = unsafe { dup2(read_end, target_fd) };
        if ret < 0 {
            let e = get_errno();
            unsafe {
                close(read_end);
            }
            return Err(RedirectError::DupFailed {
                src: read_end,
                dst: target_fd,
                errno: e,
            });
        }
        unsafe {
            close(read_end);
        }
    }

    Ok(())
}

/// Save a copy of `fd` (via `dup`) before it gets overwritten. The copy
/// is stored in `saved` so it can be restored later.
#[cfg(not(test))]
fn save_fd(fd: RawFd, saved: &mut SavedFds) -> Result<(), RedirectError> {
    // Only save if fd is currently open. We detect this with fcntl
    // F_GETFD (which returns -1 with EBADF if the fd is not open).
    let ret = unsafe { fcntl(fd, F_GETFD) };
    if ret < 0 {
        // fd is not currently open — nothing to save.
        return Ok(());
    }
    let copy = unsafe { dup(fd) };
    if copy < 0 {
        return Err(RedirectError::DupFailed {
            src: fd,
            dst: -1,
            errno: get_errno(),
        });
    }
    // Set close-on-exec on the saved copy so it doesn't leak into
    // child processes.
    unsafe {
        fcntl(copy, F_SETFD, FD_CLOEXEC);
    }
    saved.saves.push((copy, fd));
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Redirect, RedirectOp};

    // ── default_fd ───────────────────────────────────────────────────

    #[test]
    fn default_fd_input() {
        assert_eq!(default_fd(RedirectOp::Input), 0);
    }

    #[test]
    fn default_fd_output() {
        assert_eq!(default_fd(RedirectOp::Output), 1);
    }

    #[test]
    fn default_fd_append() {
        assert_eq!(default_fd(RedirectOp::Append), 1);
    }

    #[test]
    fn default_fd_heredoc() {
        assert_eq!(default_fd(RedirectOp::HereDoc), 0);
    }

    #[test]
    fn default_fd_dup_output() {
        assert_eq!(default_fd(RedirectOp::DupOutput), 1);
    }

    #[test]
    fn default_fd_dup_input() {
        assert_eq!(default_fd(RedirectOp::DupInput), 0);
    }

    #[test]
    fn default_fd_read_write() {
        assert_eq!(default_fd(RedirectOp::ReadWrite), 0);
    }

    // ── open_flags ───────────────────────────────────────────────────

    #[test]
    fn open_flags_input_is_rdonly() {
        assert_eq!(open_flags(RedirectOp::Input), O_RDONLY);
    }

    #[test]
    fn open_flags_output_has_wronly_creat_trunc() {
        let flags = open_flags(RedirectOp::Output);
        assert_ne!(flags & O_WRONLY, 0);
        assert_ne!(flags & O_CREAT, 0);
        assert_ne!(flags & O_TRUNC, 0);
    }

    #[test]
    fn open_flags_append_has_wronly_creat_append() {
        let flags = open_flags(RedirectOp::Append);
        assert_ne!(flags & O_WRONLY, 0);
        assert_ne!(flags & O_CREAT, 0);
        assert_ne!(flags & O_APPEND, 0);
    }

    #[test]
    fn open_flags_read_write_has_rdwr_creat() {
        let flags = open_flags(RedirectOp::ReadWrite);
        assert_ne!(flags & O_RDWR, 0);
        assert_ne!(flags & O_CREAT, 0);
    }

    #[test]
    fn open_flags_dup_ops_return_zero() {
        assert_eq!(open_flags(RedirectOp::DupOutput), 0);
        assert_eq!(open_flags(RedirectOp::DupInput), 0);
        assert_eq!(open_flags(RedirectOp::HereDoc), 0);
    }

    // ── parse_dup_target ─────────────────────────────────────────────

    #[test]
    fn parse_dup_target_fd_number() {
        assert_eq!(parse_dup_target("2").unwrap(), DupTarget::Fd(2));
    }

    #[test]
    fn parse_dup_target_close() {
        assert_eq!(parse_dup_target("-").unwrap(), DupTarget::Close);
    }

    #[test]
    fn parse_dup_target_zero() {
        assert_eq!(parse_dup_target("0").unwrap(), DupTarget::Fd(0));
    }

    #[test]
    fn parse_dup_target_large_fd() {
        assert_eq!(parse_dup_target("99").unwrap(), DupTarget::Fd(99));
    }

    #[test]
    fn parse_dup_target_invalid() {
        let err = parse_dup_target("abc").unwrap_err();
        match err {
            RedirectError::InvalidFdTarget { target } => assert_eq!(target, "abc"),
            _ => panic!("expected InvalidFdTarget"),
        }
    }

    #[test]
    fn parse_dup_target_empty() {
        assert!(parse_dup_target("").is_err());
    }

    #[test]
    fn parse_dup_target_negative() {
        // "-1" is not valid — only "-" (close) is.
        // However, "-1" parses as fd -1 since i32 allows it. This is
        // still useful to test the parse path.
        assert_eq!(parse_dup_target("-1").unwrap(), DupTarget::Fd(-1));
    }

    // ── resolve_fd ───────────────────────────────────────────────────

    #[test]
    fn resolve_fd_explicit() {
        let redir = Redirect {
            fd: Some(2),
            op: RedirectOp::Output,
            target: "err.log".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 2);
    }

    #[test]
    fn resolve_fd_default_output() {
        let redir = Redirect {
            fd: None,
            op: RedirectOp::Output,
            target: "out.txt".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 1);
    }

    #[test]
    fn resolve_fd_default_input() {
        let redir = Redirect {
            fd: None,
            op: RedirectOp::Input,
            target: "in.txt".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 0);
    }

    #[test]
    fn resolve_fd_explicit_zero() {
        let redir = Redirect {
            fd: Some(0),
            op: RedirectOp::Output,
            target: "file".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 0);
    }

    #[test]
    fn resolve_fd_high_number() {
        let redir = Redirect {
            fd: Some(99),
            op: RedirectOp::Input,
            target: "file".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 99);
    }

    // ── strip_heredoc_tabs ───────────────────────────────────────────

    #[test]
    fn strip_tabs_basic() {
        let input = "\thello\n\tworld";
        assert_eq!(strip_heredoc_tabs(input), "hello\nworld");
    }

    #[test]
    fn strip_tabs_mixed_indentation() {
        let input = "\t\tline1\n\tline2\nline3";
        assert_eq!(strip_heredoc_tabs(input), "line1\nline2\nline3");
    }

    #[test]
    fn strip_tabs_no_tabs() {
        let input = "hello\nworld";
        assert_eq!(strip_heredoc_tabs(input), "hello\nworld");
    }

    #[test]
    fn strip_tabs_empty() {
        assert_eq!(strip_heredoc_tabs(""), "");
    }

    #[test]
    fn strip_tabs_only_tabs() {
        let input = "\t\t\n\t";
        assert_eq!(strip_heredoc_tabs(input), "\n");
    }

    #[test]
    fn strip_tabs_preserves_spaces() {
        let input = "\t  hello\n\t  world";
        assert_eq!(strip_heredoc_tabs(input), "  hello\n  world");
    }

    #[test]
    fn strip_tabs_single_line() {
        assert_eq!(strip_heredoc_tabs("\thello"), "hello");
    }

    #[test]
    fn strip_tabs_preserves_trailing_newline() {
        let input = "\thello\n\tworld\n";
        assert_eq!(strip_heredoc_tabs(input), "hello\nworld\n");
    }

    #[test]
    fn strip_tabs_no_trailing_newline() {
        let input = "\thello\n\tworld";
        assert_eq!(strip_heredoc_tabs(input), "hello\nworld");
    }

    // ── Redirect integration tests (pure logic) ──────────────────────

    #[test]
    fn dup_target_for_stderr_to_stdout() {
        // 2>&1
        let redir = Redirect {
            fd: Some(2),
            op: RedirectOp::DupOutput,
            target: "1".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 2);
        let target = parse_dup_target(&redir.target).unwrap();
        assert_eq!(target, DupTarget::Fd(1));
    }

    #[test]
    fn dup_target_close_fd() {
        // 2>&-
        let redir = Redirect {
            fd: Some(2),
            op: RedirectOp::DupOutput,
            target: "-".to_string(),
        };
        let target = parse_dup_target(&redir.target).unwrap();
        assert_eq!(target, DupTarget::Close);
    }

    #[test]
    fn redirect_list_order_preserved() {
        // Simulates `cmd > out 2>&1` — ordering matters per POSIX.
        let redirects = vec![
            Redirect {
                fd: None,
                op: RedirectOp::Output,
                target: "out.txt".to_string(),
            },
            Redirect {
                fd: Some(2),
                op: RedirectOp::DupOutput,
                target: "1".to_string(),
            },
        ];

        // First redirect: stdout -> out.txt
        assert_eq!(resolve_fd(&redirects[0]), 1); // stdout

        // Second redirect: stderr -> dup of fd 1 (which is now out.txt)
        assert_eq!(resolve_fd(&redirects[1]), 2); // stderr
        assert_eq!(
            parse_dup_target(&redirects[1].target).unwrap(),
            DupTarget::Fd(1)
        );
    }

    #[test]
    fn redirect_order_matters_reversed() {
        // `cmd 2>&1 > out` — different semantics from `cmd > out 2>&1`.
        let redirects = vec![
            Redirect {
                fd: Some(2),
                op: RedirectOp::DupOutput,
                target: "1".to_string(),
            },
            Redirect {
                fd: None,
                op: RedirectOp::Output,
                target: "out.txt".to_string(),
            },
        ];

        // First: dup stderr from stdout (before stdout is redirected)
        assert_eq!(resolve_fd(&redirects[0]), 2);

        // Second: redirect stdout to file
        assert_eq!(resolve_fd(&redirects[1]), 1);
    }

    #[test]
    fn multiple_file_redirects() {
        // cmd < in > out 2> err
        let redirects = vec![
            Redirect {
                fd: None,
                op: RedirectOp::Input,
                target: "in".to_string(),
            },
            Redirect {
                fd: None,
                op: RedirectOp::Output,
                target: "out".to_string(),
            },
            Redirect {
                fd: Some(2),
                op: RedirectOp::Output,
                target: "err".to_string(),
            },
        ];

        assert_eq!(resolve_fd(&redirects[0]), 0); // stdin
        assert_eq!(open_flags(redirects[0].op), O_RDONLY);

        assert_eq!(resolve_fd(&redirects[1]), 1); // stdout
        assert_ne!(open_flags(redirects[1].op) & O_TRUNC, 0);

        assert_eq!(resolve_fd(&redirects[2]), 2); // stderr
        assert_ne!(open_flags(redirects[2].op) & O_TRUNC, 0);
    }

    #[test]
    fn append_redirect_flags() {
        let redir = Redirect {
            fd: None,
            op: RedirectOp::Append,
            target: "log.txt".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 1);
        let flags = open_flags(redir.op);
        assert_ne!(flags & O_APPEND, 0);
        assert_eq!(flags & O_TRUNC, 0); // append must NOT truncate
    }

    #[test]
    fn heredoc_defaults_to_stdin() {
        let redir = Redirect {
            fd: None,
            op: RedirectOp::HereDoc,
            target: "line1\nline2\n".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 0);
    }

    #[test]
    fn heredoc_with_explicit_fd() {
        let redir = Redirect {
            fd: Some(3),
            op: RedirectOp::HereDoc,
            target: "data".to_string(),
        };
        assert_eq!(resolve_fd(&redir), 3);
    }

    // ── SavedFds ─────────────────────────────────────────────────────

    #[test]
    fn saved_fds_default_is_empty() {
        let saved = SavedFds::default();
        assert!(saved.saves.is_empty());
    }

    #[test]
    fn saved_fds_restore_empty_succeeds() {
        let saved = SavedFds::new();
        assert!(saved.restore().is_ok());
    }

    // ── Error display ────────────────────────────────────────────────

    #[test]
    fn error_display_open_failed() {
        let err = RedirectError::OpenFailed {
            path: "/no/such/file".to_string(),
            errno: 2,
        };
        let msg = format!("{err}");
        assert!(msg.contains("/no/such/file"));
        assert!(msg.contains("errno 2"));
    }

    #[test]
    fn error_display_invalid_fd_target() {
        let err = RedirectError::InvalidFdTarget {
            target: "abc".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("abc"));
    }

    #[test]
    fn error_display_bad_fd_number() {
        let err = RedirectError::BadFdNumber { fd: 99 };
        let msg = format!("{err}");
        assert!(msg.contains("99"));
    }

    #[test]
    fn error_display_dup_failed() {
        let err = RedirectError::DupFailed {
            src: 3,
            dst: 1,
            errno: 9,
        };
        let msg = format!("{err}");
        assert!(msg.contains("dup2(3, 1)"));
    }

    #[test]
    fn error_display_close_failed() {
        let err = RedirectError::CloseFailed { fd: 5, errno: 9 };
        let msg = format!("{err}");
        assert!(msg.contains("close(5)"));
    }

    #[test]
    fn error_display_pipe_failed() {
        let err = RedirectError::PipeFailed { errno: 24 };
        let msg = format!("{err}");
        assert!(msg.contains("pipe()"));
    }

    #[test]
    fn error_display_write_failed() {
        let err = RedirectError::WriteFailed { errno: 28 };
        let msg = format!("{err}");
        assert!(msg.contains("write"));
    }
}
