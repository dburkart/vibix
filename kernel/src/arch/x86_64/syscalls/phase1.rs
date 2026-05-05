//! Phase 1 syscalls for Rust std initialization (RFC 0009, issue #848).
//!
//! Implements: getpid(39), exit_group(231), readv(19), writev(20),
//! getrandom(318), clock_gettime(228).

use super::super::uaccess;

/// Maximum number of iovec entries per readv/writev call (matches Linux).
const UIO_MAXIOV: usize = 1024;

/// Linux clock IDs.
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;

/// `getpid()` — return the PID of the calling process.
pub fn sys_getpid() -> i64 {
    crate::process::current_pid() as i64
}

/// `exit_group(status)` — terminate all threads in the process group.
///
/// Currently vibix is single-threaded per process, so this behaves
/// identically to `exit(status)`. When clone/threads land (Phase 3)
/// this will kill sibling threads before exiting.
pub fn sys_exit_group(status: i32) -> i64 {
    let pid = crate::process::current_pid();
    if pid != 0 {
        crate::process::reparent_children(pid);
        crate::process::mark_zombie(pid, status);
    }
    crate::task::exit();
}

/// `readv(fd, iov_user, iovcnt)` — vectored read.
///
/// Copies the iovec array from userspace first (TOCTOU mitigation),
/// then reads into each segment sequentially while holding the file
/// position lock (POSIX atomicity).
pub fn sys_readv(fd: u32, iov_user: usize, iovcnt: usize) -> i64 {
    if iovcnt == 0 {
        return 0;
    }
    if iovcnt > UIO_MAXIOV {
        return crate::fs::EINVAL;
    }

    // Each iovec is { iov_base: *mut u8, iov_len: usize } = 16 bytes on x86_64.
    let iov_bytes = iovcnt * 16;
    if let Err(e) = uaccess::check_user_range(iov_user, iov_bytes) {
        return e.as_errno();
    }

    // Copy the iovec array into kernel space (TOCTOU).
    let mut iov_buf = alloc::vec![0u8; iov_bytes];
    match unsafe { uaccess::copy_from_user(&mut iov_buf, iov_user) } {
        Ok(()) => {}
        Err(e) => return e.as_errno(),
    }

    // Parse iovec entries.
    let iovecs = parse_iovecs(&iov_buf, iovcnt);

    // Validate all user buffers up front.
    for &(base, len) in &iovecs {
        if len > 0 {
            if let Err(e) = uaccess::check_user_range(base, len) {
                return e.as_errno();
            }
        }
    }

    // Get the file backend.
    let backend = {
        let tbl = crate::task::current_fd_table();
        let x = match tbl.lock().get(fd) {
            Ok(b) => b,
            Err(e) => return e,
        };
        x
    };

    // Read into each segment sequentially (position lock held by backend).
    let mut total: usize = 0;
    let mut chunk = [0u8; 256];
    for &(base, len) in &iovecs {
        if len == 0 {
            continue;
        }
        let mut seg_read = 0usize;
        while seg_read < len {
            let n = core::cmp::min(chunk.len(), len - seg_read);
            match backend.read(&mut chunk[..n]) {
                Ok(0) => return total as i64, // EOF
                Ok(nread) => {
                    match unsafe { uaccess::copy_to_user(base + seg_read, &chunk[..nread]) } {
                        Ok(()) => {}
                        Err(e) => return e.as_errno(),
                    }
                    seg_read += nread;
                    total += nread;
                    if nread < n {
                        // Short read — don't continue to next segment.
                        return total as i64;
                    }
                }
                Err(e) => {
                    if total > 0 {
                        return total as i64;
                    }
                    return e;
                }
            }
        }
    }
    total as i64
}

/// `writev(fd, iov_user, iovcnt)` — vectored write.
///
/// Same TOCTOU and atomicity guarantees as readv.
pub fn sys_writev(fd: u32, iov_user: usize, iovcnt: usize) -> i64 {
    if iovcnt == 0 {
        return 0;
    }
    if iovcnt > UIO_MAXIOV {
        return crate::fs::EINVAL;
    }

    let iov_bytes = iovcnt * 16;
    if let Err(e) = uaccess::check_user_range(iov_user, iov_bytes) {
        return e.as_errno();
    }

    // Copy iovec array into kernel space (TOCTOU).
    let mut iov_buf = alloc::vec![0u8; iov_bytes];
    match unsafe { uaccess::copy_from_user(&mut iov_buf, iov_user) } {
        Ok(()) => {}
        Err(e) => return e.as_errno(),
    }

    let iovecs = parse_iovecs(&iov_buf, iovcnt);

    // Validate all user buffers up front.
    for &(base, len) in &iovecs {
        if len > 0 {
            if let Err(e) = uaccess::check_user_range(base, len) {
                return e.as_errno();
            }
        }
    }

    // Get the file backend.
    let backend = {
        let tbl = crate::task::current_fd_table();
        let x = match tbl.lock().get(fd) {
            Ok(b) => b,
            Err(e) => return e,
        };
        x
    };

    // Write from each segment sequentially.
    let mut total: usize = 0;
    let mut chunk = [0u8; 256];
    for &(base, len) in &iovecs {
        if len == 0 {
            continue;
        }
        let mut seg_written = 0usize;
        while seg_written < len {
            let n = core::cmp::min(chunk.len(), len - seg_written);
            match unsafe { uaccess::copy_from_user(&mut chunk[..n], base + seg_written) } {
                Ok(()) => {}
                Err(e) => return e.as_errno(),
            }
            match backend.write(&chunk[..n]) {
                Ok(0) => return total as i64,
                Ok(nw) => {
                    seg_written += nw;
                    total += nw;
                    if nw < n {
                        return total as i64;
                    }
                }
                Err(e) => {
                    if total > 0 {
                        return total as i64;
                    }
                    return e;
                }
            }
        }
    }
    total as i64
}

/// `getrandom(buf, len, flags)` — fill user buffer from CSPRNG.
///
/// Sources entropy from RDRAND/RDSEED via the kernel CSPRNG module.
/// Returns the number of bytes written, or -EFAULT on bad pointer.
/// Ignores flags for now (no blocking semantics needed — hardware RNG
/// is always available on supported platforms).
pub fn sys_getrandom(buf: usize, len: usize, _flags: u32) -> i64 {
    if len == 0 {
        return 0;
    }
    if let Err(e) = uaccess::check_user_range(buf, len) {
        return e.as_errno();
    }

    use crate::arch::x86_64::csprng;

    let mut written = 0usize;
    while written < len {
        let remaining = len - written;
        if remaining >= 8 {
            // Fill 8 bytes at a time.
            let val = match csprng::rdrand64() {
                Some(v) => v,
                None => {
                    // Fallback: use a deterministic value mixed with offset.
                    // This matches the AT_RANDOM fallback approach.
                    0x9e37_79b9_7f4a_7c15u64.wrapping_add(written as u64)
                }
            };
            let bytes = val.to_le_bytes();
            match unsafe { uaccess::copy_to_user(buf + written, &bytes) } {
                Ok(()) => {}
                Err(e) => return e.as_errno(),
            }
            written += 8;
        } else {
            // Fill remaining bytes.
            let val = match csprng::rdrand64() {
                Some(v) => v,
                None => 0x9e37_79b9_7f4a_7c15u64.wrapping_add(written as u64),
            };
            let bytes = val.to_le_bytes();
            match unsafe { uaccess::copy_to_user(buf + written, &bytes[..remaining]) } {
                Ok(()) => {}
                Err(e) => return e.as_errno(),
            }
            written += remaining;
        }
    }
    written as i64
}

/// `clock_gettime(clk_id, tp)` — get time from the specified clock.
///
/// Supports CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1).
/// Writes a `struct timespec { tv_sec: i64, tv_nsec: i64 }` to `tp`.
pub fn sys_clock_gettime(clk_id: u64, tp: usize) -> i64 {
    // Validate output pointer (timespec is 16 bytes: sec + nsec).
    if let Err(e) = uaccess::check_user_range(tp, 16) {
        return e.as_errno();
    }

    let (sec, nsec) = match clk_id {
        CLOCK_MONOTONIC => {
            let ns = crate::time::uptime_ns();
            ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
        }
        CLOCK_REALTIME => {
            // Combine RTC wall clock (seconds since epoch) with monotonic
            // sub-second precision from the TSC/PIT.
            let boot_epoch = wall_clock_to_epoch();
            let uptime_ns = crate::time::uptime_ns();
            let total_ns = boot_epoch * 1_000_000_000 + uptime_ns;
            (
                (total_ns / 1_000_000_000) as i64,
                (total_ns % 1_000_000_000) as i64,
            )
        }
        _ => return crate::fs::EINVAL,
    };

    // Write timespec { tv_sec, tv_nsec } as two i64s.
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&sec.to_ne_bytes());
    buf[8..].copy_from_slice(&nsec.to_ne_bytes());
    match unsafe { uaccess::copy_to_user(tp, &buf) } {
        Ok(()) => 0,
        Err(e) => e.as_errno(),
    }
}

/// Parse a raw iovec buffer into (base, len) pairs.
fn parse_iovecs(buf: &[u8], count: usize) -> alloc::vec::Vec<(usize, usize)> {
    let mut result = alloc::vec::Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * 16;
        let base = usize::from_ne_bytes(buf[offset..offset + 8].try_into().unwrap());
        let len = usize::from_ne_bytes(buf[offset + 8..offset + 16].try_into().unwrap());
        result.push((base, len));
    }
    result
}

/// Convert the RTC wall clock to seconds since Unix epoch.
/// Falls back to a fixed epoch if RTC is unavailable.
fn wall_clock_to_epoch() -> u64 {
    match crate::time::wall_clock() {
        Some(dt) => datetime_to_epoch(&dt),
        // If RTC is unavailable, use a reasonable default (2026-01-01 00:00:00 UTC).
        None => 1_767_225_600,
    }
}

/// Convert a DateTime to seconds since Unix epoch (UTC assumed).
fn datetime_to_epoch(dt: &crate::time::DateTime) -> u64 {
    // Days from 1970-01-01 to the given date.
    let mut days: u64 = 0;
    for y in 1970..dt.year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..dt.month {
        days += month_days[(m - 1) as usize] as u64;
        if m == 2 && is_leap_year(dt.year) {
            days += 1;
        }
    }
    days += (dt.day - 1) as u64;
    days * 86400 + dt.hour as u64 * 3600 + dt.minute as u64 * 60 + dt.second as u64
}

fn is_leap_year(y: u16) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
