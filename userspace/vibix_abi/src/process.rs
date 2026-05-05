//! Process management syscall wrappers for vibix.

use crate::syscall;

const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;
const SYS_KILL: u64 = 62;
const SYS_GETPID: u64 = 39;
const SYS_EXIT_GROUP: u64 = 231;

/// Fork the current process.
#[inline]
pub unsafe fn fork() -> i64 {
    syscall::syscall0(SYS_FORK)
}

/// Execute a program.
#[inline]
pub unsafe fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    syscall::syscall3(SYS_EXECVE, path as u64, argv as u64, envp as u64)
}

/// Exit the current thread.
#[inline]
pub unsafe fn exit(status: i32) -> ! {
    syscall::syscall1(SYS_EXIT, status as u64);
    // unreachable
    loop {
        core::hint::spin_loop();
    }
}

/// Exit all threads in the process.
#[inline]
pub unsafe fn exit_group(status: i32) -> ! {
    syscall::syscall1(SYS_EXIT_GROUP, status as u64);
    loop {
        core::hint::spin_loop();
    }
}

/// Wait for a child process.
/// Returns pid on success, negative errno on failure.
#[inline]
pub unsafe fn wait4(pid: i32, status: *mut i32, options: i32, rusage: u64) -> i64 {
    syscall::syscall4(SYS_WAIT4, pid as u64, status as u64, options as u64, rusage)
}

/// Send a signal to a process.
#[inline]
pub unsafe fn kill(pid: i32, sig: i32) -> i64 {
    syscall::syscall2(SYS_KILL, pid as u64, sig as u64)
}

/// Get the current process ID.
#[inline]
pub unsafe fn getpid() -> i64 {
    syscall::syscall0(SYS_GETPID)
}

// Signal numbers.
pub const SIGKILL: i32 = 9;

// wait4 options.
pub const WNOHANG: i32 = 1;
