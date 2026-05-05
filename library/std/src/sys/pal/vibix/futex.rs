//! Futex implementation for vibix.
//!
//! This module provides the futex interface that `sys/sync/` primitives
//! (Mutex, Condvar, RwLock, Once, Parker) use when configured for futex mode.

use crate::sync::atomic::Atomic;
use crate::time::Duration;

/// An atomic for use as a futex that is at least 32-bits but may be larger.
pub type Futex = Atomic<Primitive>;
/// Must be the underlying type of Futex.
pub type Primitive = u32;

/// An atomic for use as a futex that is at least 8-bits but may be larger.
pub type SmallFutex = Atomic<SmallPrimitive>;
/// Must be the underlying type of SmallFutex.
pub type SmallPrimitive = u32;

/// Syscall number for futex.
const SYS_FUTEX: u64 = 202;

/// Futex operations.
const FUTEX_WAIT_PRIVATE: u32 = 0 | 128;
const FUTEX_WAKE_PRIVATE: u32 = 1 | 128;

/// Timespec matching Linux's `struct timespec`.
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Wait on a futex.
///
/// Atomically checks `*futex == expected`, and if so, suspends the thread
/// until woken by `futex_wake`, a timeout expires, or a spurious wakeup.
///
/// Returns `true` if woken normally (or spuriously), `false` on timeout.
pub fn futex_wait(futex: &Atomic<u32>, expected: u32, timeout: Option<Duration>) -> bool {
    let timespec = timeout.map(|dur| {
        let tv_sec = i64::try_from(dur.as_secs()).unwrap_or(i64::MAX);
        let tv_nsec = i64::from(dur.subsec_nanos());
        Timespec { tv_sec, tv_nsec }
    });

    let timeout_ptr = match timespec.as_ref() {
        Some(ts) => ts as *const Timespec as u64,
        None => 0,
    };

    let ret = unsafe {
        vibix_abi::syscall::syscall4(
            SYS_FUTEX,
            futex as *const Atomic<u32> as u64,
            FUTEX_WAIT_PRIVATE as u64,
            expected as u64,
            timeout_ptr,
        )
    };

    // -ETIMEDOUT = -110
    ret != -110
}

/// Wake one thread waiting on the futex.
///
/// Returns `true` if a thread was woken.
#[inline]
pub fn futex_wake(futex: &Atomic<u32>) -> bool {
    unsafe {
        vibix_abi::syscall::syscall3(
            SYS_FUTEX,
            futex as *const Atomic<u32> as u64,
            FUTEX_WAKE_PRIVATE as u64,
            1,
        ) > 0
    }
}

/// Wake all threads waiting on the futex.
#[inline]
pub fn futex_wake_all(futex: &Atomic<u32>) {
    unsafe {
        vibix_abi::syscall::syscall3(
            SYS_FUTEX,
            futex as *const Atomic<u32> as u64,
            FUTEX_WAKE_PRIVATE as u64,
            i32::MAX as u64,
        );
    }
}
