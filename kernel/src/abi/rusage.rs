//! Resource-usage types pinned to the Linux x86_64 syscall ABI.
//!
//! `struct rusage` is the payload for `getrusage(2)`. The layout matches
//! `include/uapi/linux/resource.h` — 18 fields of `long` (8 bytes each
//! on x86_64), totalling 144 bytes.
//!
//! `struct timeval` is the sub-structure used for `ru_utime` / `ru_stime`.

/// `struct timeval` — seconds + microseconds, matching Linux x86_64.
///
/// Both fields are `long` (i64) on x86_64.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// `who` argument constants for `getrusage(2)`.
pub const RUSAGE_SELF: i32 = 0;
pub const RUSAGE_CHILDREN: i32 = -1;
pub const RUSAGE_THREAD: i32 = 1;

/// `struct rusage` — resource usage statistics, matching the Linux
/// x86_64 layout exactly (18 × `long` = 144 bytes).
///
/// Most fields are unused stubs (zeroed). `ru_utime` and `ru_stime`
/// may optionally be populated from scheduler tick counts.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Rusage {
    /// User CPU time used.
    pub ru_utime: Timeval,
    /// System CPU time used.
    pub ru_stime: Timeval,
    /// Maximum resident set size (kilobytes).
    pub ru_maxrss: i64,
    /// Integral shared memory size.
    pub ru_ixrss: i64,
    /// Integral unshared data size.
    pub ru_idrss: i64,
    /// Integral unshared stack size.
    pub ru_isrss: i64,
    /// Page reclaims (soft page faults).
    pub ru_minflt: i64,
    /// Page faults (hard page faults).
    pub ru_majflt: i64,
    /// Swaps.
    pub ru_nswap: i64,
    /// Block input operations.
    pub ru_inblock: i64,
    /// Block output operations.
    pub ru_oublock: i64,
    /// IPC messages sent.
    pub ru_msgsnd: i64,
    /// IPC messages received.
    pub ru_msgrcv: i64,
    /// Signals received.
    pub ru_nsignals: i64,
    /// Voluntary context switches.
    pub ru_nvcsw: i64,
    /// Involuntary context switches.
    pub ru_nivcsw: i64,
}

// Compile-time layout pins.
const _: () = assert!(core::mem::size_of::<Timeval>() == 16);
const _: () = assert!(core::mem::size_of::<Rusage>() == 144);
const _: () = assert!(core::mem::align_of::<Rusage>() == 8);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn timeval_layout() {
        assert_eq!(size_of::<Timeval>(), 16);
        assert_eq!(align_of::<Timeval>(), 8);
    }

    #[test]
    fn rusage_layout_matches_linux() {
        assert_eq!(size_of::<Rusage>(), 144);
        assert_eq!(align_of::<Rusage>(), 8);
    }

    #[test]
    fn default_is_zeroed() {
        let r = Rusage::default();
        assert_eq!(r.ru_utime.tv_sec, 0);
        assert_eq!(r.ru_utime.tv_usec, 0);
        assert_eq!(r.ru_stime.tv_sec, 0);
        assert_eq!(r.ru_stime.tv_usec, 0);
        assert_eq!(r.ru_maxrss, 0);
    }
}
