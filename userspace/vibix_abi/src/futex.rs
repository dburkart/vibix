//! Futex syscall wrappers for vibix.
//!
//! Provides FUTEX_WAIT and FUTEX_WAKE operations matching the Linux interface.

use core::sync::atomic::AtomicU32;

use crate::syscall;
use crate::thread::Timespec;

/// Syscall number for futex.
const SYS_FUTEX: u64 = 202;

/// Futex operations.
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

/// Perform a futex wait operation.
///
/// Atomically checks that `*futex == expected` and suspends the calling thread.
/// Returns when woken by `futex_wake`, on timeout, or spuriously.
///
/// - `futex`: the futex word to wait on
/// - `expected`: the expected value
/// - `timeout`: optional relative timeout
///
/// Returns `true` if woken normally, `false` on timeout.
#[inline]
pub fn futex_wait(futex: &AtomicU32, expected: u32, timeout: Option<&Timespec>) -> bool {
    let timeout_ptr = match timeout {
        Some(ts) => ts as *const Timespec as u64,
        None => 0,
    };
    let ret = unsafe {
        syscall::syscall4(
            SYS_FUTEX,
            futex as *const AtomicU32 as u64,
            FUTEX_WAIT_PRIVATE as u64,
            expected as u64,
            timeout_ptr,
        )
    };
    // -ETIMEDOUT = -110
    ret != -110
}

/// Wake up to `count` threads waiting on the futex.
///
/// Returns the number of threads woken.
#[inline]
pub fn futex_wake(futex: &AtomicU32, count: u32) -> i64 {
    unsafe {
        syscall::syscall3(
            SYS_FUTEX,
            futex as *const AtomicU32 as u64,
            FUTEX_WAKE_PRIVATE as u64,
            count as u64,
        )
    }
}
