//! Credential-query syscalls: `getuid(2)`, `geteuid(2)`, `getgid(2)`,
//! `getegid(2)`.
//!
//! These are POSIX-mandated read-only accessors for the caller's
//! real/effective user and group IDs. Per POSIX.1-2017 they are
//! *infallible* — the manpage signature is `uid_t getuid(void)` with no
//! errno contract — so every dispatch arm here returns the requested ID
//! as a non-negative `i64`, never a negated errno.
//!
//! ## Wait-free Arc-snapshot read path
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
//! Because these syscalls are read-only and never dereference a
//! user-space pointer, they do not depend on the `vfs_creds` feature
//! flag — the flag guards VFS paths that still straddle the
//! Workstream A/B transition. `getuid`-family calls have no such
//! mid-transition concern and wire up unconditionally.

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
