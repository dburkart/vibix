//! Thread lifecycle wrappers for vibix.
//!
//! Provides `clone`-based thread creation and related syscalls.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::syscall;

/// Syscall numbers (Linux x86_64 ABI).
const SYS_SCHED_YIELD: u64 = 24;
const SYS_NANOSLEEP: u64 = 35;
const SYS_CLONE: u64 = 56;
const SYS_GETTID: u64 = 186;
const SYS_SET_TID_ADDRESS: u64 = 218;

/// Clone flags for pthreads-style threading.
pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;

/// The standard set of clone flags for creating a new thread.
pub const CLONE_THREAD_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_SYSVSEM;

/// Timespec structure matching Linux's `struct timespec`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Create a new thread via the `clone` syscall.
///
/// - `flags`: combination of CLONE_* constants
/// - `stack_top`: pointer to the top of the child's stack
/// - `parent_tid`: written with the child's TID (CLONE_PARENT_SETTID)
/// - `child_tid`: address set for CLONE_CHILD_CLEARTID (cleared on exit)
/// - `tls`: TLS base for the new thread (CLONE_SETTLS)
///
/// On success in the parent, returns the child TID (> 0).
/// On success in the child, returns 0.
/// On failure, returns a negative errno.
///
/// # Safety
///
/// The caller must ensure stack_top is a valid stack pointer and that
/// the entry function is properly set up (e.g., via assembly trampoline).
#[inline]
pub unsafe fn clone(
    flags: u64,
    stack_top: *mut u8,
    parent_tid: *mut u32,
    child_tid: *mut u32,
    tls: u64,
) -> i64 {
    // clone(flags, stack, parent_tid, child_tid, tls)
    // Note: Linux x86_64 clone ABI puts child_tid in r10 and tls in r8,
    // matching syscall4/5 register assignment.
    unsafe {
        syscall::syscall5(
            SYS_CLONE,
            flags,
            stack_top as u64,
            parent_tid as u64,
            child_tid as u64,
            tls,
        )
    }
}

/// Yield the current thread's timeslice.
#[inline]
pub fn sched_yield() {
    unsafe {
        syscall::syscall0(SYS_SCHED_YIELD);
    }
}

/// Sleep for the specified duration.
///
/// Returns 0 on success, or a negative errno (e.g., -EINTR) if interrupted.
#[inline]
pub fn nanosleep(req: &Timespec) -> i64 {
    unsafe { syscall::syscall2(SYS_NANOSLEEP, req as *const Timespec as u64, 0) }
}

/// Get the current thread's TID.
#[inline]
pub fn gettid() -> i64 {
    unsafe { syscall::syscall0(SYS_GETTID) }
}

/// Set the clear_child_tid address for the calling thread.
#[inline]
pub fn set_tid_address(tidptr: *mut u32) -> i64 {
    unsafe { syscall::syscall1(SYS_SET_TID_ADDRESS, tidptr as u64) }
}

/// Wait for a thread to exit by futex-waiting on its `clear_child_tid` word.
///
/// The kernel atomically sets `*tid_addr = 0` and does `FUTEX_WAKE` on the
/// address when the thread exits (if CLONE_CHILD_CLEARTID was set).
#[inline]
pub fn join_thread(tid_addr: &AtomicU32) {
    loop {
        let val = tid_addr.load(Ordering::Acquire);
        if val == 0 {
            return;
        }
        // futex_wait on the tid address until it becomes 0
        crate::futex::futex_wait(tid_addr, val, None);
    }
}
