//! Resource-limit and resource-usage syscalls (issues #927, #928).
//!
//! Implements:
//!   - getrlimit(97)  — read one resource limit for the calling process.
//!   - setrlimit(160) — write one resource limit for the calling process.
//!   - prlimit64(302) — read and/or write one resource limit, optionally
//!                       targeting another process (pid == 0 → self).
//!   - getrusage(98)  — return resource usage (currently zeroed stub).

use super::super::uaccess;
use crate::abi::rlimit::{Rlimit, RLIM_NLIMITS};
use crate::abi::rusage::{Rusage, RUSAGE_CHILDREN, RUSAGE_SELF, RUSAGE_THREAD};

/// POSIX errno constants used by this module.
const EINVAL: i64 = -22;
const ESRCH: i64 = -3;
const EPERM: i64 = -1;

/// `getrlimit(resource, *rlim)` — copy the soft/hard limit for
/// `resource` into the user-supplied `struct rlimit`.
pub fn sys_getrlimit(resource: u32, rlim_uva: usize) -> i64 {
    if resource as usize >= RLIM_NLIMITS {
        return EINVAL;
    }
    if let Err(e) = uaccess::check_user_range(rlim_uva, core::mem::size_of::<Rlimit>()) {
        return e.as_errno();
    }
    let pid = crate::process::current_pid();
    if pid == 0 {
        return ESRCH;
    }
    match crate::process::get_rlimit(pid, resource) {
        Some(lim) => {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &lim as *const Rlimit as *const u8,
                    core::mem::size_of::<Rlimit>(),
                )
            };
            match unsafe { uaccess::copy_to_user(rlim_uva, bytes) } {
                Ok(()) => 0,
                Err(e) => e.as_errno(),
            }
        }
        None => EINVAL,
    }
}

/// `setrlimit(resource, *rlim)` — set the soft/hard limit for
/// `resource` from the user-supplied `struct rlimit`.
pub fn sys_setrlimit(resource: u32, rlim_uva: usize) -> i64 {
    if resource as usize >= RLIM_NLIMITS {
        return EINVAL;
    }
    if let Err(e) = uaccess::check_user_range(rlim_uva, core::mem::size_of::<Rlimit>()) {
        return e.as_errno();
    }
    let mut buf = [0u8; core::mem::size_of::<Rlimit>()];
    match unsafe { uaccess::copy_from_user(&mut buf, rlim_uva) } {
        Ok(()) => {}
        Err(e) => return e.as_errno(),
    }
    // SAFETY: Rlimit is repr(C) with no padding holes, and buf has
    // exactly the right size. Any bit pattern is valid for u64 fields.
    let new_lim: Rlimit = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Rlimit) };

    // Validate: soft must not exceed hard.
    if new_lim.rlim_cur > new_lim.rlim_max {
        return EINVAL;
    }

    let pid = crate::process::current_pid();
    if pid == 0 {
        return ESRCH;
    }
    match crate::process::set_rlimit(pid, resource, new_lim) {
        Some(_old) => 0,
        None => EINVAL,
    }
}

/// `prlimit64(pid, resource, *new_rlim, *old_rlim)` — atomic
/// get-and-set of a resource limit, optionally on another process.
///
/// - `pid == 0` targets the calling process.
/// - `new_rlim == NULL` skips the set.
/// - `old_rlim == NULL` skips the get.
pub fn sys_prlimit64(pid_arg: u32, resource: u32, new_uva: usize, old_uva: usize) -> i64 {
    if resource as usize >= RLIM_NLIMITS {
        return EINVAL;
    }

    let target_pid = if pid_arg == 0 {
        crate::process::current_pid()
    } else {
        pid_arg
    };
    if target_pid == 0 {
        return ESRCH;
    }

    // If targeting a different process, stub: only allow self for now.
    // A full implementation would need capability checks (CAP_SYS_RESOURCE).
    if pid_arg != 0 {
        let caller_pid = crate::process::current_pid();
        if caller_pid != target_pid {
            return EPERM;
        }
    }

    // Read the new limit from userspace if provided.
    let new_lim = if new_uva != 0 {
        if let Err(e) = uaccess::check_user_range(new_uva, core::mem::size_of::<Rlimit>()) {
            return e.as_errno();
        }
        let mut buf = [0u8; core::mem::size_of::<Rlimit>()];
        match unsafe { uaccess::copy_from_user(&mut buf, new_uva) } {
            Ok(()) => {}
            Err(e) => return e.as_errno(),
        }
        let lim: Rlimit = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Rlimit) };
        if lim.rlim_cur > lim.rlim_max {
            return EINVAL;
        }
        Some(lim)
    } else {
        None
    };

    // Validate old_uva range if provided.
    if old_uva != 0 {
        if let Err(e) = uaccess::check_user_range(old_uva, core::mem::size_of::<Rlimit>()) {
            return e.as_errno();
        }
    }

    // Perform the get (and optionally set) atomically w.r.t. the
    // process table lock.
    if let Some(new) = new_lim {
        // get-then-set
        let old = match crate::process::set_rlimit(target_pid, resource, new) {
            Some(old) => old,
            None => return EINVAL,
        };
        if old_uva != 0 {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &old as *const Rlimit as *const u8,
                    core::mem::size_of::<Rlimit>(),
                )
            };
            match unsafe { uaccess::copy_to_user(old_uva, bytes) } {
                Ok(()) => {}
                Err(e) => return e.as_errno(),
            }
        }
    } else {
        // get only
        if old_uva != 0 {
            let lim = match crate::process::get_rlimit(target_pid, resource) {
                Some(l) => l,
                None => return EINVAL,
            };
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &lim as *const Rlimit as *const u8,
                    core::mem::size_of::<Rlimit>(),
                )
            };
            match unsafe { uaccess::copy_to_user(old_uva, bytes) } {
                Ok(()) => {}
                Err(e) => return e.as_errno(),
            }
        }
    }

    0
}

/// `getrusage(who, *rusage)` — return resource usage statistics.
///
/// Currently returns a zeroed `struct rusage` for `RUSAGE_SELF` and
/// `RUSAGE_CHILDREN`. Optionally populates `ru_utime`/`ru_stime`
/// from scheduler ticks if available.
pub fn sys_getrusage(who: i32, rusage_uva: usize) -> i64 {
    match who {
        RUSAGE_SELF | RUSAGE_CHILDREN | RUSAGE_THREAD => {}
        _ => return EINVAL,
    }

    if let Err(e) = uaccess::check_user_range(rusage_uva, core::mem::size_of::<Rusage>()) {
        return e.as_errno();
    }

    // For now, return a zeroed struct. A future implementation could
    // populate ru_utime/ru_stime from the scheduler's tick counter.
    let usage = Rusage::default();

    let bytes = unsafe {
        core::slice::from_raw_parts(
            &usage as *const Rusage as *const u8,
            core::mem::size_of::<Rusage>(),
        )
    };
    match unsafe { uaccess::copy_to_user(rusage_uva, bytes) } {
        Ok(()) => 0,
        Err(e) => e.as_errno(),
    }
}
