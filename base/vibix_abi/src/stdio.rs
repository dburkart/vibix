//! Standard I/O helpers for vibix userspace.
//!
//! Provides `read_stdin`, `write_stdout` and `write_stderr` using the
//! `readv`/`writev` syscalls (nr 19/20).

use crate::syscall;

/// Syscall numbers (Linux x86_64).
const SYS_READV: u64 = 19;
const SYS_WRITEV: u64 = 20;

/// Standard file descriptors.
const STDIN_FD: u64 = 0;
const STDOUT_FD: u64 = 1;
const STDERR_FD: u64 = 2;

/// An iovec for vectored I/O, matching the Linux `struct iovec` layout.
#[repr(C)]
struct IoVec {
    iov_base: *const u8,
    iov_len: usize,
}

/// Read from stdin into `buf`. Returns the number of bytes read, or a
/// negative errno on failure.
pub fn read_stdin(buf: &mut [u8]) -> i64 {
    let iov = IoVec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    unsafe { syscall::syscall3(SYS_READV, STDIN_FD, &iov as *const IoVec as u64, 1) }
}

/// Write `buf` to stdout.  Returns the number of bytes written, or a negative
/// errno on failure.
pub fn write_stdout(buf: &[u8]) -> i64 {
    writev(STDOUT_FD, buf)
}

/// Write `buf` to stderr.  Returns the number of bytes written, or a negative
/// errno on failure.
pub fn write_stderr(buf: &[u8]) -> i64 {
    writev(STDERR_FD, buf)
}

/// Issue a `writev` syscall with a single iovec entry.
fn writev(fd: u64, buf: &[u8]) -> i64 {
    let iov = IoVec {
        iov_base: buf.as_ptr(),
        iov_len: buf.len(),
    };
    unsafe { syscall::syscall3(SYS_WRITEV, fd, &iov as *const IoVec as u64, 1) }
}
