//! `sys_poll`, `sys_ppoll`, `sys_select`, `sys_pselect6` — POSIX multiplexed
//! readiness syscalls.
//!
//! All four share a single two-pass scan:
//!
//! 1. **Probe pass** — iterate every fd, call `FileBackend::poll` with a
//!    `PollTable::probe()` (no wait-queue registration). If any fd is ready,
//!    fill revents and return the ready count immediately.
//! 2. **Wait pass** — if nothing was ready in the probe pass, rebuild the
//!    table in wait mode (`PollTable::wait(tid)`). Re-call each backend's
//!    `poll()` to register interest, then recheck under the ring buffer lock
//!    (wait-latching invariant from RFC 0003), then `block_current()`.
//!    On wake, run a final probe pass to collect results.
//!
//! Timeout handling (simplified, no timer integration yet):
//! - `timeout == 0` (ms or zero-valued timespec/timeval) → probe-only.
//! - `timeout < 0` or non-zero → block until ready (no deadline, same as ∞).
//!
//! `sys_select` and `sys_pselect6` convert fd_set bitmasks to a `Vec<PollFd>`
//! before calling the shared scan, then scatter results back into the caller's
//! fd_sets.
//!
//! All blocking paths are gated on `#[cfg(target_os = "none")]`. The ABI
//! types and fd_set conversion helpers are always compiled so they can be
//! tested on the host.

#[cfg(target_os = "none")]
use alloc::vec::Vec;

#[cfg(target_os = "none")]
use crate::fs::EINVAL;

// ── ABI types ────────────────────────────────────────────────────────────────

/// Linux `struct pollfd` layout (8 bytes, packed by the ABI).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PollFd {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
}

/// Linux `struct timeval` (used by `sys_select`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Linux `struct timespec` (used by `sys_ppoll` / `sys_pselect6`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Maximum `nfds` accepted by `poll` / `ppoll`.
pub const NFDS_MAX: usize = 4096;

/// Maximum `nfds` accepted by `select` / `pselect6` (Linux ABI limit).
pub const NFDS_SELECT_MAX: usize = 1024;

/// Size in bytes of a `fd_set` for `NFDS_SELECT_MAX` file descriptors
/// (1024 bits = 128 bytes).
pub const FD_SET_BYTES: usize = NFDS_SELECT_MAX / 8;

// ── fd_set helpers (always compiled — used in host tests too) ────────────────

/// Test whether bit `fd` is set in a 128-byte fd_set.
#[inline]
pub fn fd_isset(fds: &[u8; FD_SET_BYTES], fd: usize) -> bool {
    fds[fd / 8] & (1u8 << (fd % 8)) != 0
}

/// Set bit `fd` in a 128-byte fd_set.
#[inline]
pub fn fd_set(fds: &mut [u8; FD_SET_BYTES], fd: usize) {
    fds[fd / 8] |= 1u8 << (fd % 8);
}

/// Clear bit `fd` in a 128-byte fd_set.
#[inline]
pub fn fd_clr(fds: &mut [u8; FD_SET_BYTES], fd: usize) {
    fds[fd / 8] &= !(1u8 << (fd % 8));
}

// ── Timeout conversion helpers ────────────────────────────────────────────────

/// Returns `true` if the timeout means "poll-only, don't block".
/// `None` = null pointer (infinite wait).
fn is_zero_timeout_ms(timeout_ms: i64) -> bool {
    timeout_ms == 0
}

fn is_zero_timeval(tv: &Timeval) -> bool {
    tv.tv_sec == 0 && tv.tv_usec == 0
}

fn is_zero_timespec(ts: &Timespec) -> bool {
    ts.tv_sec == 0 && ts.tv_nsec == 0
}

// ── Kernel-only scan logic ────────────────────────────────────────────────────

#[cfg(target_os = "none")]
use crate::arch::x86_64::uaccess;
#[cfg(target_os = "none")]
use crate::fs::EBADF;
#[cfg(target_os = "none")]
use crate::poll::{PollMask, PollTable};

/// Flags that are always returned in `revents` even if not in `events`.
#[cfg(target_os = "none")]
const ALWAYS_REPORTED: PollMask =
    crate::poll::POLLERR | crate::poll::POLLHUP | crate::poll::POLLNVAL;

/// Run a single probe pass over `fds`.
///
/// For each entry: negative `fd` → skip (revents stays 0). EBADF / not open →
/// POLLNVAL. Otherwise call the backend's `poll()`, filter by
/// `events | ALWAYS_REPORTED`, and set `revents`.
///
/// Returns the number of fds with non-zero revents.
#[cfg(target_os = "none")]
fn probe_pass(fds: &mut [PollFd], tbl: &mut PollTable) -> usize {
    let fd_table = crate::task::current_fd_table();
    let guard = fd_table.lock();
    let mut ready = 0usize;
    for pfd in fds.iter_mut() {
        pfd.revents = 0;
        if pfd.fd < 0 {
            continue;
        }
        match guard.get(pfd.fd as u32) {
            Err(_) => {
                pfd.revents = crate::poll::POLLNVAL;
                ready += 1;
            }
            Ok(backend) => {
                let mask = backend.poll(tbl);
                let reported = mask & (pfd.events | ALWAYS_REPORTED);
                if reported != 0 {
                    pfd.revents = reported;
                    ready += 1;
                }
            }
        }
    }
    ready
}

/// Two-pass poll scan over `fds`. Returns ready count, or a negative errno.
///
/// `probe_only` — if true, run only the probe pass (timeout == 0).
#[cfg(target_os = "none")]
fn do_poll(fds: &mut [PollFd], probe_only: bool) -> i64 {
    use crate::task;

    // ── Pass 1: probe ────────────────────────────────────────────────────────
    {
        let mut tbl = PollTable::probe();
        let ready = probe_pass(fds, &mut tbl);
        if ready > 0 || probe_only {
            return ready as i64;
        }
    } // PollTable dropped → cancel_all() (no-op for probe mode)

    // ── Pass 2: register interest, recheck, block ────────────────────────────
    let tid = task::current_id();
    {
        let mut tbl = PollTable::wait(tid);
        // Register on every backend's wait queue.
        {
            let fd_table = crate::task::current_fd_table();
            let guard = fd_table.lock();
            for pfd in fds.iter_mut() {
                if pfd.fd < 0 {
                    continue;
                }
                if let Ok(backend) = guard.get(pfd.fd as u32) {
                    backend.poll(&mut tbl);
                }
            }
        }
        // Wait-latching: recheck readiness *after* registering so a concurrent
        // producer that fired between probe and register is not missed.
        {
            let mut tbl2 = PollTable::probe();
            let ready = probe_pass(fds, &mut tbl2);
            if ready > 0 {
                // Already ready — cancel registrations and return.
                drop(tbl); // cancel_all()
                return ready as i64;
            }
        }
        // Park.  If a wake fires before block_current(), wake_pending is set
        // and block_current() returns immediately (wait-latching invariant).
        task::block_current();
        // tbl dropped here → cancel_all() on all pollers.
    }

    // ── Final probe after wake ───────────────────────────────────────────────
    // Check if a signal interrupted us.
    let signal_pending =
        crate::process::with_signal_state_for_task(tid, |s| s.pending != 0).unwrap_or(false);
    if signal_pending {
        return crate::fs::EINTR;
    }

    let mut tbl = PollTable::probe();
    probe_pass(fds, &mut tbl) as i64
}

// ── Syscall implementations ───────────────────────────────────────────────────

/// `poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)` — Linux ABI.
///
/// # Safety
/// `fds_uva` must be a valid userspace pointer to `nfds` `struct pollfd` records.
#[cfg(target_os = "none")]
pub unsafe fn sys_poll(fds_uva: u64, nfds: u64, timeout_ms: i64) -> i64 {
    if nfds as usize > NFDS_MAX {
        return EINVAL;
    }
    let n = nfds as usize;

    // Fast path: ≤ 8 fds on the stack.
    if n <= 8 {
        let mut arr = [PollFd::default(); 8];
        let slice = &mut arr[..n];
        if let Err(e) = uaccess::copy_from_user(
            unsafe { core::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, n * 8) },
            fds_uva as usize,
        ) {
            return e.as_errno();
        }
        let result = do_poll(slice, is_zero_timeout_ms(timeout_ms));
        if result >= 0 {
            let _ = uaccess::copy_to_user(fds_uva as usize, unsafe {
                core::slice::from_raw_parts(slice.as_ptr() as *const u8, n * 8)
            });
        }
        result
    } else {
        let mut fds_vec: Vec<PollFd> = Vec::with_capacity(n);
        // SAFETY: PollFd is #[repr(C)] with no padding, valid for any bit pattern.
        unsafe { fds_vec.set_len(n) };
        if let Err(e) = uaccess::copy_from_user(
            unsafe { core::slice::from_raw_parts_mut(fds_vec.as_mut_ptr() as *mut u8, n * 8) },
            fds_uva as usize,
        ) {
            return e.as_errno();
        }
        let result = do_poll(&mut fds_vec, is_zero_timeout_ms(timeout_ms));
        if result >= 0 {
            let _ = uaccess::copy_to_user(fds_uva as usize, unsafe {
                core::slice::from_raw_parts(fds_vec.as_ptr() as *const u8, n * 8)
            });
        }
        result
    }
}

/// `ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)`
///
/// sigmask is accepted but not applied (signal-mask atomicity is future work).
///
/// # Safety
/// `fds_uva` must be a valid userspace pointer; `ts_uva` may be 0 (NULL = infinite wait).
#[cfg(target_os = "none")]
pub unsafe fn sys_ppoll(fds_uva: u64, nfds: u64, ts_uva: u64, _sigmask_uva: u64) -> i64 {
    if nfds as usize > NFDS_MAX {
        return EINVAL;
    }
    let n = nfds as usize;

    let probe_only = if ts_uva == 0 {
        false // NULL → infinite wait
    } else {
        let mut ts = Timespec::default();
        if let Err(e) = uaccess::copy_from_user(
            unsafe { core::slice::from_raw_parts_mut(&mut ts as *mut Timespec as *mut u8, 16) },
            ts_uva as usize,
        ) {
            return e.as_errno();
        }
        is_zero_timespec(&ts)
    };

    if n <= 8 {
        let mut arr = [PollFd::default(); 8];
        let slice = &mut arr[..n];
        if let Err(e) = uaccess::copy_from_user(
            unsafe { core::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, n * 8) },
            fds_uva as usize,
        ) {
            return e.as_errno();
        }
        let result = do_poll(slice, probe_only);
        if result >= 0 {
            let _ = uaccess::copy_to_user(fds_uva as usize, unsafe {
                core::slice::from_raw_parts(slice.as_ptr() as *const u8, n * 8)
            });
        }
        result
    } else {
        let mut fds_vec: Vec<PollFd> = Vec::with_capacity(n);
        unsafe { fds_vec.set_len(n) };
        if let Err(e) = uaccess::copy_from_user(
            unsafe { core::slice::from_raw_parts_mut(fds_vec.as_mut_ptr() as *mut u8, n * 8) },
            fds_uva as usize,
        ) {
            return e.as_errno();
        }
        let result = do_poll(&mut fds_vec, probe_only);
        if result >= 0 {
            let _ = uaccess::copy_to_user(fds_uva as usize, unsafe {
                core::slice::from_raw_parts(fds_vec.as_ptr() as *const u8, n * 8)
            });
        }
        result
    }
}

// ── select / pselect6 ────────────────────────────────────────────────────────

/// Synthesise a `Vec<PollFd>` from three optional fd_set bitmaps.
///
/// `nfds` is the exclusive upper bound (Linux: "highest fd + 1"). Any fd in
/// [0, nfds) that appears in at least one of the three sets gets an entry;
/// fds not in any set are skipped entirely.
#[cfg(target_os = "none")]
fn select_build_fds(
    nfds: usize,
    readfds: Option<&[u8; FD_SET_BYTES]>,
    writefds: Option<&[u8; FD_SET_BYTES]>,
    exceptfds: Option<&[u8; FD_SET_BYTES]>,
) -> Vec<PollFd> {
    let mut fds: Vec<PollFd> = Vec::new();
    for fd in 0..nfds {
        let mut events: u16 = 0;
        if readfds.map(|s| fd_isset(s, fd)).unwrap_or(false) {
            events |= crate::poll::POLLIN | crate::poll::POLLRDNORM;
        }
        if writefds.map(|s| fd_isset(s, fd)).unwrap_or(false) {
            events |= crate::poll::POLLOUT | crate::poll::POLLWRNORM;
        }
        if exceptfds.map(|s| fd_isset(s, fd)).unwrap_or(false) {
            events |= crate::poll::POLLPRI;
        }
        if events != 0 {
            fds.push(PollFd {
                fd: fd as i32,
                events,
                revents: 0,
            });
        }
    }
    fds
}

/// Scatter `fds` results back into three optional fd_set bitmaps. Returns the
/// number of (fd, set) pairs that are ready (a single fd counts once per set
/// it's ready in, matching Linux `select(2)` return semantics).
#[cfg(target_os = "none")]
fn select_scatter_results(
    nfds: usize,
    fds: &[PollFd],
    mut readfds: Option<&mut [u8; FD_SET_BYTES]>,
    mut writefds: Option<&mut [u8; FD_SET_BYTES]>,
    mut exceptfds: Option<&mut [u8; FD_SET_BYTES]>,
) -> usize {
    // First zero out all three sets; we'll re-populate from fds.
    if let Some(r) = readfds.as_deref_mut() {
        r.fill(0);
    }
    if let Some(w) = writefds.as_deref_mut() {
        w.fill(0);
    }
    if let Some(e) = exceptfds.as_deref_mut() {
        e.fill(0);
    }

    let mut count = 0usize;
    for pfd in fds {
        if pfd.fd < 0 || pfd.fd as usize >= nfds {
            continue;
        }
        let fd = pfd.fd as usize;
        let rev = pfd.revents;
        if rev == 0 {
            continue;
        }
        if let Some(r) = readfds.as_deref_mut() {
            if rev & (crate::poll::POLLIN | crate::poll::POLLHUP | crate::poll::POLLRDNORM) != 0 {
                fd_set(r, fd);
                count += 1;
            }
        }
        if let Some(w) = writefds.as_deref_mut() {
            if rev & (crate::poll::POLLOUT | crate::poll::POLLWRNORM) != 0 {
                fd_set(w, fd);
                count += 1;
            }
        }
        if let Some(e) = exceptfds.as_deref_mut() {
            if rev & crate::poll::POLLPRI != 0 {
                fd_set(e, fd);
                count += 1;
            }
        }
    }
    count
}

/// `select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)`
///
/// # Safety
/// All non-NULL uva pointers must be valid userspace addresses.
#[cfg(target_os = "none")]
pub unsafe fn sys_select(
    nfds: u64,
    readfds_uva: u64,
    writefds_uva: u64,
    exceptfds_uva: u64,
    timeout_uva: u64,
) -> i64 {
    if nfds as usize > NFDS_SELECT_MAX {
        return EINVAL;
    }
    let n = nfds as usize;

    // Read optional timeout.
    let probe_only = if timeout_uva == 0 {
        false
    } else {
        let mut tv = Timeval::default();
        if let Err(e) = uaccess::copy_from_user(
            unsafe { core::slice::from_raw_parts_mut(&mut tv as *mut Timeval as *mut u8, 16) },
            timeout_uva as usize,
        ) {
            return e.as_errno();
        }
        is_zero_timeval(&tv)
    };

    // Read fd_sets.
    let mut read_buf = [0u8; FD_SET_BYTES];
    let mut write_buf = [0u8; FD_SET_BYTES];
    let mut exc_buf = [0u8; FD_SET_BYTES];

    if readfds_uva != 0 {
        if let Err(e) = uaccess::copy_from_user(&mut read_buf, readfds_uva as usize) {
            return e.as_errno();
        }
    }
    if writefds_uva != 0 {
        if let Err(e) = uaccess::copy_from_user(&mut write_buf, writefds_uva as usize) {
            return e.as_errno();
        }
    }
    if exceptfds_uva != 0 {
        if let Err(e) = uaccess::copy_from_user(&mut exc_buf, exceptfds_uva as usize) {
            return e.as_errno();
        }
    }

    let readfds = if readfds_uva != 0 {
        Some(&read_buf)
    } else {
        None
    };
    let writefds = if writefds_uva != 0 {
        Some(&write_buf)
    } else {
        None
    };
    let exceptfds = if exceptfds_uva != 0 {
        Some(&exc_buf)
    } else {
        None
    };

    let mut fds = select_build_fds(n, readfds, writefds, exceptfds);

    let result = do_poll(&mut fds, probe_only);
    if result < 0 {
        return result;
    }

    // Scatter results.
    let mut read_out = [0u8; FD_SET_BYTES];
    let mut write_out = [0u8; FD_SET_BYTES];
    let mut exc_out = [0u8; FD_SET_BYTES];
    let ready = select_scatter_results(
        n,
        &fds,
        if readfds_uva != 0 {
            Some(&mut read_out)
        } else {
            None
        },
        if writefds_uva != 0 {
            Some(&mut write_out)
        } else {
            None
        },
        if exceptfds_uva != 0 {
            Some(&mut exc_out)
        } else {
            None
        },
    );

    if readfds_uva != 0 {
        let _ = uaccess::copy_to_user(readfds_uva as usize, &read_out);
    }
    if writefds_uva != 0 {
        let _ = uaccess::copy_to_user(writefds_uva as usize, &write_out);
    }
    if exceptfds_uva != 0 {
        let _ = uaccess::copy_to_user(exceptfds_uva as usize, &exc_out);
    }

    ready as i64
}

/// `pselect6(int nfds, fd_set *r, fd_set *w, fd_set *e, const struct timespec *ts, const sigset_t *sigmask)`
///
/// sigmask is accepted but not applied (signal-mask atomicity is future work).
///
/// # Safety
/// All non-NULL uva pointers must be valid userspace addresses.
#[cfg(target_os = "none")]
pub unsafe fn sys_pselect6(
    nfds: u64,
    readfds_uva: u64,
    writefds_uva: u64,
    exceptfds_uva: u64,
    ts_uva: u64,
    _sigmask_uva: u64,
) -> i64 {
    if nfds as usize > NFDS_SELECT_MAX {
        return EINVAL;
    }
    let n = nfds as usize;

    let probe_only = if ts_uva == 0 {
        false
    } else {
        let mut ts = Timespec::default();
        if let Err(e) = uaccess::copy_from_user(
            unsafe { core::slice::from_raw_parts_mut(&mut ts as *mut Timespec as *mut u8, 16) },
            ts_uva as usize,
        ) {
            return e.as_errno();
        }
        is_zero_timespec(&ts)
    };

    let mut read_buf = [0u8; FD_SET_BYTES];
    let mut write_buf = [0u8; FD_SET_BYTES];
    let mut exc_buf = [0u8; FD_SET_BYTES];

    if readfds_uva != 0 {
        if let Err(e) = uaccess::copy_from_user(&mut read_buf, readfds_uva as usize) {
            return e.as_errno();
        }
    }
    if writefds_uva != 0 {
        if let Err(e) = uaccess::copy_from_user(&mut write_buf, writefds_uva as usize) {
            return e.as_errno();
        }
    }
    if exceptfds_uva != 0 {
        if let Err(e) = uaccess::copy_from_user(&mut exc_buf, exceptfds_uva as usize) {
            return e.as_errno();
        }
    }

    let readfds = if readfds_uva != 0 {
        Some(&read_buf)
    } else {
        None
    };
    let writefds = if writefds_uva != 0 {
        Some(&write_buf)
    } else {
        None
    };
    let exceptfds = if exceptfds_uva != 0 {
        Some(&exc_buf)
    } else {
        None
    };

    let mut fds = select_build_fds(n, readfds, writefds, exceptfds);

    let result = do_poll(&mut fds, probe_only);
    if result < 0 {
        return result;
    }

    let mut read_out = [0u8; FD_SET_BYTES];
    let mut write_out = [0u8; FD_SET_BYTES];
    let mut exc_out = [0u8; FD_SET_BYTES];
    let ready = select_scatter_results(
        n,
        &fds,
        if readfds_uva != 0 {
            Some(&mut read_out)
        } else {
            None
        },
        if writefds_uva != 0 {
            Some(&mut write_out)
        } else {
            None
        },
        if exceptfds_uva != 0 {
            Some(&mut exc_out)
        } else {
            None
        },
    );

    if readfds_uva != 0 {
        let _ = uaccess::copy_to_user(readfds_uva as usize, &read_out);
    }
    if writefds_uva != 0 {
        let _ = uaccess::copy_to_user(writefds_uva as usize, &write_out);
    }
    if exceptfds_uva != 0 {
        let _ = uaccess::copy_to_user(exceptfds_uva as usize, &exc_out);
    }

    ready as i64
}

// ── Host unit tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── fd_set bit helpers ────────────────────────────────────────────────────

    #[test]
    fn fd_isset_clear_by_default() {
        let fds = [0u8; FD_SET_BYTES];
        for fd in 0..NFDS_SELECT_MAX {
            assert!(!fd_isset(&fds, fd));
        }
    }

    #[test]
    fn fd_set_and_isset() {
        let mut fds = [0u8; FD_SET_BYTES];
        fd_set(&mut fds, 0);
        fd_set(&mut fds, 7);
        fd_set(&mut fds, 8);
        fd_set(&mut fds, 63);
        fd_set(&mut fds, 1023);
        assert!(fd_isset(&fds, 0));
        assert!(fd_isset(&fds, 7));
        assert!(fd_isset(&fds, 8));
        assert!(fd_isset(&fds, 63));
        assert!(fd_isset(&fds, 1023));
        assert!(!fd_isset(&fds, 1));
        assert!(!fd_isset(&fds, 64));
    }

    #[test]
    fn fd_clr_clears_bit() {
        let mut fds = [0xffu8; FD_SET_BYTES];
        fd_clr(&mut fds, 5);
        assert!(!fd_isset(&fds, 5));
        assert!(fd_isset(&fds, 4));
        assert!(fd_isset(&fds, 6));
    }

    // ── Timeout helpers ───────────────────────────────────────────────────────

    #[test]
    fn zero_timeout_ms_is_probe_only() {
        assert!(is_zero_timeout_ms(0));
        assert!(!is_zero_timeout_ms(-1));
        assert!(!is_zero_timeout_ms(100));
    }

    #[test]
    fn zero_timeval() {
        assert!(is_zero_timeval(&Timeval {
            tv_sec: 0,
            tv_usec: 0
        }));
        assert!(!is_zero_timeval(&Timeval {
            tv_sec: 0,
            tv_usec: 1
        }));
        assert!(!is_zero_timeval(&Timeval {
            tv_sec: 1,
            tv_usec: 0
        }));
    }

    #[test]
    fn zero_timespec() {
        assert!(is_zero_timespec(&Timespec {
            tv_sec: 0,
            tv_nsec: 0
        }));
        assert!(!is_zero_timespec(&Timespec {
            tv_sec: 0,
            tv_nsec: 1
        }));
        assert!(!is_zero_timespec(&Timespec {
            tv_sec: 1,
            tv_nsec: 0
        }));
    }

    // ── ABI layout ────────────────────────────────────────────────────────────

    #[test]
    fn pollfd_layout() {
        assert_eq!(core::mem::size_of::<PollFd>(), 8);
        assert_eq!(core::mem::align_of::<PollFd>(), 4);
        // fd at offset 0, events at 4, revents at 6
        let p = PollFd {
            fd: 0x12345678,
            events: 0xABCD,
            revents: 0xEF01,
        };
        let bytes: [u8; 8] = unsafe { core::mem::transmute(p) };
        assert_eq!(
            i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            0x12345678
        );
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), 0xABCD);
        assert_eq!(u16::from_ne_bytes([bytes[6], bytes[7]]), 0xEF01);
    }

    #[test]
    fn timeval_layout() {
        assert_eq!(core::mem::size_of::<Timeval>(), 16);
    }

    #[test]
    fn timespec_layout() {
        assert_eq!(core::mem::size_of::<Timespec>(), 16);
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn fd_set_bytes_is_128() {
        assert_eq!(FD_SET_BYTES, 128);
    }

    #[test]
    fn nfds_constants() {
        assert_eq!(NFDS_MAX, 4096);
        assert_eq!(NFDS_SELECT_MAX, 1024);
    }
}
