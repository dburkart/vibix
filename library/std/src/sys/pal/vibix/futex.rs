use crate::ptr::null;
use crate::sync::atomic::Atomic;
use crate::time::Duration;

/// An atomic for use as a futex that is at least 32-bits but may be larger
pub type Futex = Atomic<Primitive>;
/// Must be the underlying type of Futex
pub type Primitive = u32;

/// An atomic for use as a futex that is at least 8-bits but may be larger.
pub type SmallFutex = Atomic<SmallPrimitive>;
/// Must be the underlying type of SmallFutex
pub type SmallPrimitive = u32;

// Linux futex constants (same ABI as vibix)
const SYS_FUTEX: u64 = 202; // x86_64
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE: u32 = 1;
const FUTEX_PRIVATE_FLAG: u32 = 128;

/// Waits for a `futex_wake` operation to wake us.
///
/// Returns directly if the futex doesn't hold the expected value.
///
/// Returns false on timeout, and true in all other cases.
pub fn futex_wait(futex: &Atomic<u32>, expected: u32, timeout: Option<Duration>) -> bool {
    use crate::sync::atomic::Ordering::Relaxed;

    // Calculate the timeout as an absolute timespec.
    let timespec = timeout.and_then(|d| {
        // Use a relative timeout with FUTEX_WAIT_BITSET + CLOCK_MONOTONIC
        let secs: i64 = d.as_secs().try_into().ok()?;
        let nsecs: i64 = d.subsec_nanos().try_into().ok()?;
        Some(libc::timespec { tv_sec: secs, tv_nsec: nsecs })
    });

    loop {
        if futex.load(Relaxed) != expected {
            return true;
        }

        let ts_ptr = timespec
            .as_ref()
            .map_or(null(), |t| t as *const libc::timespec);

        let r = unsafe {
            // Use FUTEX_WAIT_BITSET with full bitmask for absolute timeout
            vibix_abi::syscall::syscall6(
                SYS_FUTEX,
                futex as *const Atomic<u32> as u64,
                (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG) as u64,
                expected as u64,
                ts_ptr as u64,
                0, // uaddr2 (unused)
                !0u32 as u64, // full bitmask
            )
        };

        match (r < 0).then(|| -r as i32) {
            Some(libc::ETIMEDOUT) => return false,
            Some(libc::EINTR) => continue,
            _ => return true,
        }
    }
}

/// Wakes up one thread that's blocked on `futex_wait` on this futex.
///
/// Returns true if this actually woke up such a thread,
/// or false if no thread was waiting on this futex.
pub fn futex_wake(futex: &Atomic<u32>) -> bool {
    let r = unsafe {
        vibix_abi::syscall::syscall3(
            SYS_FUTEX,
            futex as *const Atomic<u32> as u64,
            (FUTEX_WAKE | FUTEX_PRIVATE_FLAG) as u64,
            1,
        )
    };
    r > 0
}

/// Wakes up all threads that are waiting on `futex_wait` on this futex.
pub fn futex_wake_all(futex: &Atomic<u32>) {
    unsafe {
        vibix_abi::syscall::syscall3(
            SYS_FUTEX,
            futex as *const Atomic<u32> as u64,
            (FUTEX_WAKE | FUTEX_PRIVATE_FLAG) as u64,
            i32::MAX as u64,
        );
    }
}
