//! Credential syscalls: read (`getuid(2)` / `geteuid(2)` / `getgid(2)` /
//! `getegid(2)`) and write (`setuid(2)` / `setgid(2)` / `setreuid(2)` /
//! `setregid(2)` / `setresuid(2)` / `setresgid(2)`).
//!
//! The read arms are POSIX-mandated infallible accessors for the
//! caller's real/effective IDs; they return a non-negative `i64`, never
//! a negated errno. The write arms implement POSIX.1-2017 §2.4
//! saved-set-user-ID semantics: they validate the requested transition
//! against the caller's current `{ruid, euid, suid}` set (and the
//! privileged euid==0 bypass), build a fresh [`Credential`], and swap
//! the inner `Arc` under the per-task `BlockingRwLock`.
//!
//! ## Wait-free Arc-snapshot model
//!
//! [`Task::credentials`](crate::task::Task::credentials) is a
//! `BlockingRwLock<Arc<Credential>>`. Readers take a short read-lock,
//! clone the `Arc`, drop the lock, then read the field off the cloned
//! snapshot. A concurrent `setuid(2)` writer builds a fresh
//! `Credential`, takes the write-lock, and swaps the inner `Arc`; it
//! never mutates a live `Credential` in place. The read-side thus
//! cannot tear and does not block on writers for more than the trivial
//! `Arc::clone` + lock acquire — this is the "wait-free read" model
//! called out in RFC 0004 §Credential model.
//!
//! Because these syscalls operate on the caller's own task credentials
//! rather than dereferencing a user-space pointer, they do not depend
//! on the `vfs_creds` feature flag — the flag guards VFS paths that
//! still straddle the Workstream A/B transition. `getuid`- and
//! `setuid`-family calls have no such mid-transition concern and wire
//! up unconditionally.
//!
//! ## POSIX.1-2017 decision matrix (issue #548)
//!
//! For the write arms, `u32::MAX` is the C `(uid_t)-1` sentinel. The
//! single-argument forms (`setuid`, `setgid`) reject it with `EINVAL`
//! because POSIX requires an explicit target; the pair and triple forms
//! (`setreuid`, `setresuid`, `setregid`, `setresgid`) treat it as "leave
//! this field unchanged" and so `set*reuid(-1, -1)` and
//! `set*resuid(-1, -1, -1)` are valid no-op successes.
//!
//! | Syscall        | Privileged (euid==0)                              | Unprivileged rule                                                                                  |
//! |----------------|---------------------------------------------------|----------------------------------------------------------------------------------------------------|
//! | `setuid(u)`    | ruid=euid=suid=u                                  | Require u ∈ {ruid, suid}. Set euid=u only. (`u == euid` also accepted since euid ∈ {ruid, suid} after a prior setuid-bit exec or is already the current ID.) |
//! | `setreuid(r,e)`| any r, any e; if r!=-1 or e!=-1 & e!=old ruid, suid=new euid | Each non-(-1) target must be ∈ {old ruid, old euid, old suid}. Same suid-bump rule.         |
//! | `setresuid(r,e,s)` | any r/e/s (per -1)                            | Each non-(-1) target must be ∈ {old ruid, old euid, old suid}. suid takes `s` literally (or is unchanged if `s == -1`); no implicit bump. |
//!
//! The gid family mirrors the uid family field-for-field; the
//! "privileged" predicate is still `euid == 0` (POSIX.1: only the
//! effective *user* ID determines privilege for the `setgid` family too).

use alloc::vec::Vec;

use crate::arch::x86_64::uaccess;
use crate::fs::vfs::Credential;
use crate::fs::{EFAULT, EINVAL, EPERM};

/// Maximum number of supplementary groups a single task may carry. Issue #549
/// pins this at 32 — the smallest value RFC 0004 §Open Questions calls out as
/// reasonable for a hobby kernel and the lower bound POSIX.1-2017 permits.
/// Linux uses 65536; 32 is intentionally tight and revisitable when a
/// real-world workload bumps into it.
pub const NGROUPS_MAX: usize = 32;

// `u32::MAX` is the C `(uid_t)-1` sentinel. Named at module scope so
// the intent is obvious at every use site and a future switch to a
// signed transport (e.g. if we ever plumb `i32` through SYSCALL) is a
// one-line change.
const UID_UNCHANGED: u32 = u32::MAX;

/// `getuid(2)` — return the caller's real user ID.
///
/// POSIX: "The getuid() function shall always be successful and no
/// return value is reserved to indicate an error." We therefore return
/// the `uid` field widened to `i64` unconditionally — there is no
/// error path.
///
/// Uses the wait-free Arc-snapshot read model described at the module
/// level: [`crate::task::current_credentials`] clones the inner
/// `Arc<Credential>` under a short read-lock, then drops the lock
/// before we read the field.
pub fn sys_getuid() -> i64 {
    crate::task::current_credentials().uid as i64
}

/// `geteuid(2)` — return the caller's effective user ID.
///
/// The effective UID is what DAC permission checks consult — see
/// `default_permission` in `fs::vfs::ops`. As with `getuid`, POSIX
/// promises no error path.
pub fn sys_geteuid() -> i64 {
    crate::task::current_credentials().euid as i64
}

/// `getgid(2)` — return the caller's real group ID.
pub fn sys_getgid() -> i64 {
    crate::task::current_credentials().gid as i64
}

/// `getegid(2)` — return the caller's effective group ID.
pub fn sys_getegid() -> i64 {
    crate::task::current_credentials().egid as i64
}

/// Build a fresh `Credential` by cloning `cur` and overriding the four
/// user-side fields. The group fields and supplementary groups are
/// preserved verbatim — POSIX does not clear them on a uid transition
/// (Linux rule per RFC 0004 §945-957).
fn with_uids(cur: &Credential, uid: u32, euid: u32, suid: u32) -> Credential {
    Credential::from_task_ids(
        uid,
        euid,
        suid,
        cur.gid,
        cur.egid,
        cur.sgid,
        cur.groups.clone(),
    )
}

/// Mirror of [`with_uids`] for the group-side transitions.
fn with_gids(cur: &Credential, gid: u32, egid: u32, sgid: u32) -> Credential {
    Credential::from_task_ids(
        cur.uid,
        cur.euid,
        cur.suid,
        gid,
        egid,
        sgid,
        cur.groups.clone(),
    )
}

/// Non-root membership check for the `{ruid, euid, suid}` triple.
/// Returns `true` iff `target` equals any of the three current IDs.
/// `u32::MAX` (the `-1` sentinel) is rejected at the call site before
/// we get here; this helper deals only with real target values.
fn is_member_uid(cur: &Credential, target: u32) -> bool {
    target == cur.uid || target == cur.euid || target == cur.suid
}

fn is_member_gid(cur: &Credential, target: u32) -> bool {
    target == cur.gid || target == cur.egid || target == cur.sgid
}

/// `setuid(uid)` — POSIX.1-2017 §setuid.
///
/// - `uid == (uid_t)-1`: `EINVAL`. The single-argument form has no
///   "unchanged" sentinel; a `-1` target is always an invalid ID.
/// - `euid == 0` (privileged): set `ruid = euid = suid = uid`. This is
///   the irrevocable drop when a setuid-root process wants to shed root
///   permanently (the classic idiom: `setuid(getuid())` from root).
/// - Otherwise (unprivileged): `uid` must be `∈ {ruid, suid}`; sets
///   `euid = uid` only. `ruid` and `suid` are preserved so the caller
///   retains the authority to swap back via `seteuid(suid)` later.
///   We check membership in `{ruid, suid}` (not `{ruid, euid, suid}`):
///   the current euid is deliberately excluded to match Linux, which
///   rejects a "keep euid as-is" self-set on this path with `EPERM`
///   when neither ruid nor suid matches.
///
/// Returns `0` on success, negative errno on failure.
pub fn sys_setuid(uid: u32) -> i64 {
    if uid == UID_UNCHANGED {
        return EINVAL;
    }
    let cur = crate::task::current_credentials();
    let new_cred = if cur.euid == 0 {
        with_uids(&cur, uid, uid, uid)
    } else if uid == cur.uid || uid == cur.suid {
        with_uids(&cur, cur.uid, uid, cur.suid)
    } else {
        return EPERM;
    };
    crate::task::replace_current_credentials(new_cred);
    0
}

/// `setreuid(ruid, euid)` — POSIX.1-2017 §setreuid.
///
/// Either argument may be `(uid_t)-1` to leave that field unchanged.
/// Non-root callers must pass targets drawn from the current
/// `{ruid, euid, suid}` set. Root (euid == 0) skips the membership
/// check.
///
/// Saved-set-user-ID update rule (POSIX §setreuid, fourth paragraph):
/// if `ruid` was set (argument not `-1`), *or* `euid` was set to a
/// value different from the current real uid, then `suid` is set to
/// the new `euid`. Otherwise `suid` is unchanged. This is the
/// "drop-and-restore" mechanism for a setuid binary: after
/// `setreuid(ruid, 0)` the saved-set-uid is pinned to 0 so a later
/// `setreuid(0, 0)` (or `seteuid(0)`) succeeds via membership.
///
/// `setreuid(-1, -1)` is a valid no-op success.
pub fn sys_setreuid(ruid: u32, euid: u32) -> i64 {
    let cur = crate::task::current_credentials();
    let new_ruid = if ruid == UID_UNCHANGED { cur.uid } else { ruid };
    let new_euid = if euid == UID_UNCHANGED {
        cur.euid
    } else {
        euid
    };
    // Membership check (non-root only). Each *set* (i.e., non-(-1))
    // target must be a current member. Root bypasses.
    if cur.euid != 0 {
        if ruid != UID_UNCHANGED && !is_member_uid(&cur, ruid) {
            return EPERM;
        }
        if euid != UID_UNCHANGED && !is_member_uid(&cur, euid) {
            return EPERM;
        }
    }
    // suid-bump rule: fires when either ruid was set explicitly, or
    // euid was set to a value != current ruid. We test against the
    // *old* ruid per POSIX wording; `cur.uid` is that value.
    let suid_bump = ruid != UID_UNCHANGED || (euid != UID_UNCHANGED && euid != cur.uid);
    let new_suid = if suid_bump { new_euid } else { cur.suid };
    let new_cred = with_uids(&cur, new_ruid, new_euid, new_suid);
    crate::task::replace_current_credentials(new_cred);
    0
}

/// `setresuid(ruid, euid, suid)` — POSIX.1-2017 (Linux extension in
/// §2.4 spirit; not in POSIX.1-2017 §setresuid directly but the
/// reference the RFC follows).
///
/// Any argument may be `(uid_t)-1` to leave that field unchanged. Root
/// (euid == 0) may set any of the three to any value; non-root callers
/// must draw each non-(-1) target from the current `{ruid, euid, suid}`
/// set.
///
/// Unlike `setreuid`, there is **no** implicit `suid := euid` update:
/// `setresuid` exposes all three fields to the caller directly, so the
/// caller controls `suid` explicitly (either by passing the literal
/// value or by passing `-1` to preserve).
pub fn sys_setresuid(ruid: u32, euid: u32, suid: u32) -> i64 {
    let cur = crate::task::current_credentials();
    if cur.euid != 0 {
        if ruid != UID_UNCHANGED && !is_member_uid(&cur, ruid) {
            return EPERM;
        }
        if euid != UID_UNCHANGED && !is_member_uid(&cur, euid) {
            return EPERM;
        }
        if suid != UID_UNCHANGED && !is_member_uid(&cur, suid) {
            return EPERM;
        }
    }
    let new_ruid = if ruid == UID_UNCHANGED { cur.uid } else { ruid };
    let new_euid = if euid == UID_UNCHANGED {
        cur.euid
    } else {
        euid
    };
    let new_suid = if suid == UID_UNCHANGED {
        cur.suid
    } else {
        suid
    };
    let new_cred = with_uids(&cur, new_ruid, new_euid, new_suid);
    crate::task::replace_current_credentials(new_cred);
    0
}

/// `setgid(gid)` — POSIX.1-2017 §setgid.
///
/// Group-side mirror of [`sys_setuid`]. The privileged predicate is
/// still `euid == 0` per POSIX.1 (only the effective *user* ID confers
/// privilege; effective group ID alone does not). `gid == (gid_t)-1`
/// is `EINVAL` for the same reason `setuid(-1)` is: no unchanged
/// sentinel in the single-argument form.
pub fn sys_setgid(gid: u32) -> i64 {
    if gid == UID_UNCHANGED {
        return EINVAL;
    }
    let cur = crate::task::current_credentials();
    let new_cred = if cur.euid == 0 {
        with_gids(&cur, gid, gid, gid)
    } else if gid == cur.gid || gid == cur.sgid {
        with_gids(&cur, cur.gid, gid, cur.sgid)
    } else {
        return EPERM;
    };
    crate::task::replace_current_credentials(new_cred);
    0
}

/// `setregid(rgid, egid)` — POSIX.1-2017 §setregid.
///
/// Group-side mirror of [`sys_setreuid`], including the `sgid := new
/// egid` bump rule when the real gid is set or the effective gid
/// changes to a value `!=` old real gid.
pub fn sys_setregid(rgid: u32, egid: u32) -> i64 {
    let cur = crate::task::current_credentials();
    let new_rgid = if rgid == UID_UNCHANGED { cur.gid } else { rgid };
    let new_egid = if egid == UID_UNCHANGED {
        cur.egid
    } else {
        egid
    };
    if cur.euid != 0 {
        if rgid != UID_UNCHANGED && !is_member_gid(&cur, rgid) {
            return EPERM;
        }
        if egid != UID_UNCHANGED && !is_member_gid(&cur, egid) {
            return EPERM;
        }
    }
    let sgid_bump = rgid != UID_UNCHANGED || (egid != UID_UNCHANGED && egid != cur.gid);
    let new_sgid = if sgid_bump { new_egid } else { cur.sgid };
    let new_cred = with_gids(&cur, new_rgid, new_egid, new_sgid);
    crate::task::replace_current_credentials(new_cred);
    0
}

/// `setresgid(rgid, egid, sgid)` — group-side mirror of
/// [`sys_setresuid`]. No implicit `sgid` update; caller controls all
/// three fields.
pub fn sys_setresgid(rgid: u32, egid: u32, sgid: u32) -> i64 {
    let cur = crate::task::current_credentials();
    if cur.euid != 0 {
        if rgid != UID_UNCHANGED && !is_member_gid(&cur, rgid) {
            return EPERM;
        }
        if egid != UID_UNCHANGED && !is_member_gid(&cur, egid) {
            return EPERM;
        }
        if sgid != UID_UNCHANGED && !is_member_gid(&cur, sgid) {
            return EPERM;
        }
    }
    let new_rgid = if rgid == UID_UNCHANGED { cur.gid } else { rgid };
    let new_egid = if egid == UID_UNCHANGED {
        cur.egid
    } else {
        egid
    };
    let new_sgid = if sgid == UID_UNCHANGED {
        cur.sgid
    } else {
        sgid
    };
    let new_cred = with_gids(&cur, new_rgid, new_egid, new_sgid);
    crate::task::replace_current_credentials(new_cred);
    0
}

/// Helper for [`sys_setgroups`]: build a fresh `Credential` cloned from
/// `cur` with `groups` replacing the supplementary group list.
fn with_groups(cur: &Credential, groups: Vec<u32>) -> Credential {
    Credential::from_task_ids(
        cur.uid, cur.euid, cur.suid, cur.gid, cur.egid, cur.sgid, groups,
    )
}

/// `getgroups(size, list)` — POSIX.1-2017 §getgroups.
///
/// Returns the count of supplementary group IDs on the calling task.
///
/// - If `size == 0`, the call is a query: return the count without
///   touching `list_uva` (POSIX-mandated; `list_uva` may legally be
///   `NULL` on this path and we must not fault on it).
/// - Otherwise, copy up to `size` group IDs out to `list_uva` (a
///   `gid_t[]`, `gid_t = u32` on this ABI) and return the actual count
///   copied.
/// - If `size > 0` and `size < count`, return `EINVAL` (POSIX: "If the
///   size argument is non-zero and less than the number of group IDs,
///   `getgroups()` shall fail" with `EINVAL`).
/// - If the user buffer is invalid, return `EFAULT`.
///
/// Uses the wait-free Arc-snapshot read model — the group list is
/// cloned out from under a short read-lock before any user copy.
pub fn sys_getgroups(size: i32, list_uva: u64) -> i64 {
    let cred = crate::task::current_credentials();
    let count = cred.groups.len();
    if size == 0 {
        // Query form: report the count, do not touch the buffer.
        return count as i64;
    }
    if size < 0 {
        return EINVAL;
    }
    let size = size as usize;
    if size < count {
        return EINVAL;
    }
    // Copy the live group list out as native-endian u32s. gid_t is u32
    // on this ABI; userspace and kernel share endianness so to_ne_bytes
    // matches the C-side `gid_t` layout exactly.
    if count > 0 {
        let bytes_len = count
            .checked_mul(core::mem::size_of::<u32>())
            .expect("getgroups: NGROUPS_MAX bound prevents this overflow");
        // Stage to a kernel buffer first so we hold the user-copy bracket
        // for the minimum window.
        let mut staging: Vec<u8> = Vec::with_capacity(bytes_len);
        for gid in cred.groups.iter() {
            staging.extend_from_slice(&gid.to_ne_bytes());
        }
        match unsafe { uaccess::copy_to_user(list_uva as usize, &staging) } {
            Ok(()) => {}
            Err(_) => return EFAULT,
        }
    }
    count as i64
}

/// `setgroups(size, list)` — POSIX.1-2017 §setgroups (BSD/Linux extension
/// in POSIX.1-2017 spirit).
///
/// Replaces the calling task's supplementary group list with the
/// `size`-element vector at `list_uva`. Per RFC 0004 Workstream B wave 1,
/// `setgroups` is **root-only** — non-root callers receive `EPERM`.
/// `CAP_SETGID` is out of scope for this epic.
///
/// - `size > NGROUPS_MAX` (32): `EINVAL`. RFC 0004 §Open Questions pins
///   the bound; POSIX permits any value ≥ `_POSIX_NGROUPS_MAX` (=8).
/// - `size < 0`: `EINVAL`.
/// - `euid != 0`: `EPERM` (this epic).
/// - `list_uva` invalid for `size * sizeof(gid_t)` bytes: `EFAULT`.
///
/// On success returns 0. The list is replaced wholesale — POSIX makes no
/// promises about deduping or sorting; we preserve insertion order so
/// `getgroups` round-trips a `setgroups(g)` exactly.
pub fn sys_setgroups(size: i32, list_uva: u64) -> i64 {
    if size < 0 {
        return EINVAL;
    }
    let size = size as usize;
    if size > NGROUPS_MAX {
        return EINVAL;
    }
    let cur = crate::task::current_credentials();
    if cur.euid != 0 {
        return EPERM;
    }
    let groups = if size == 0 {
        Vec::new()
    } else {
        let bytes_len = size
            .checked_mul(core::mem::size_of::<u32>())
            .expect("setgroups: NGROUPS_MAX bound prevents this overflow");
        let mut staging = alloc::vec![0u8; bytes_len];
        match unsafe { uaccess::copy_from_user(&mut staging, list_uva as usize) } {
            Ok(()) => {}
            Err(_) => return EFAULT,
        }
        let mut out = Vec::with_capacity(size);
        for chunk in staging.chunks_exact(core::mem::size_of::<u32>()) {
            out.push(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        out
    };
    let new_cred = with_groups(&cur, groups);
    crate::task::replace_current_credentials(new_cred);
    0
}
