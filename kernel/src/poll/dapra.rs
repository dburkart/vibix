//! DAPRA — Deadline-Aware Poll Readiness with Aggregation.
//!
//! RFC 0003 §"Deadline-aware poll readiness" introduces an additive extension
//! to `sys_poll`: a per-fd soft-deadline hint + poll-group aggregation that
//! lets the scheduler batch wake-ups across fds within a latency budget.
//!
//! Three new syscalls (vibix-reserved 600–602):
//!
//! - `poll_group_create()` → `PollGroupToken` (opaque i32 handle)
//! - `poll_group_destroy(token)` → 0 on success
//! - `poll_deadline(fds, nfds, timeout_ns, group)` → ready count
//!
//! ## PollGroupToken lifecycle
//!
//! Tokens are per-process, opaque integers starting at 1. Not inherited
//! across `fork`; revoked on `execve`. Maximum 64 groups per process
//! (`POLL_GROUP_MAX`).
//!
//! ## Deferral semantics
//!
//! On first readiness event, the kernel conceptually schedules a deadline
//! timer at `now + min(deferral_ns)` across all polled fds in the group.
//! Until that timer fires (or a deferral-exempt condition appears), further
//! readiness events coalesce into the pollfd array without waking the caller.
//!
//! Deferral-exempt conditions: POLLERR, POLLHUP, POLLNVAL, signal delivery.
//! These always cause immediate wake regardless of `deferral_ns`.
//!
//! `DAPRA_MAX_DEFER_NS = 10_000_000` (10 ms) hard cap.

#[cfg(any(test, target_os = "none"))]
use alloc::collections::BTreeMap;

/// Hard cap on any single fd's `deferral_ns`. Values above are rejected
/// with EINVAL at syscall entry. 10 ms keeps DAPRA in the "interactive"
/// latency regime per RFC 0003.
pub const DAPRA_MAX_DEFER_NS: u32 = 10_000_000;

/// Maximum number of poll groups a single process may hold simultaneously.
pub const POLL_GROUP_MAX: usize = 64;

/// Opaque poll-group handle. Starts at 1; 0 is reserved for
/// "anonymous per-call group" in `sys_poll_deadline`.
pub type PollGroupToken = i32;

/// Per-process poll group table. Stores the set of live group tokens
/// for a single process. Created empty on process start; not inherited
/// across `fork`; cleared on `execve`.
///
/// The table is a simple monotonic-counter + BTreeMap. Each entry is
/// a `PollGroup` that carries the aggregation state for one group.
/// Designed for host-testability: no kernel-specific types leak into
/// the container.
#[cfg(any(test, target_os = "none"))]
pub struct PollGroupTable {
    /// Monotonic token allocator. Starts at 1; wraps at i32::MAX.
    next_token: i32,
    /// Live groups keyed by their token.
    groups: BTreeMap<PollGroupToken, PollGroup>,
}

/// A single poll group's kernel-side state. In the current implementation
/// this is a minimal placeholder — the group exists primarily as a
/// namespace for `poll_deadline` callers to share a wake-batch window.
/// The actual deferral logic (timer arming) is handled inline in
/// `sys_poll_deadline` using the per-call `min(deferral_ns)`.
#[cfg(any(test, target_os = "none"))]
pub struct PollGroup {
    /// The token that names this group (stored for diagnostics / test
    /// assertions).
    pub token: PollGroupToken,
}

#[cfg(any(test, target_os = "none"))]
impl PollGroupTable {
    /// Create an empty table. Called once per process at creation time.
    pub const fn new() -> Self {
        Self {
            next_token: 1,
            groups: BTreeMap::new(),
        }
    }

    /// Allocate a new poll group. Returns the token on success, or
    /// `Err(())` if the per-process cap (`POLL_GROUP_MAX`) is reached.
    pub fn create(&mut self) -> Result<PollGroupToken, ()> {
        if self.groups.len() >= POLL_GROUP_MAX {
            return Err(());
        }
        let token = self.next_token;
        // Wrap at i32::MAX; tokens are opaque so reuse after destroy is
        // fine — the BTreeMap ensures no live collision.
        self.next_token = if token == i32::MAX { 1 } else { token + 1 };
        // Skip tokens that are still live (extremely unlikely but
        // correct under adversarial create/destroy patterns).
        let mut t = token;
        while self.groups.contains_key(&t) {
            t = if t == i32::MAX { 1 } else { t + 1 };
            if t == token {
                // Wrapped all the way around — table is full.
                return Err(());
            }
        }
        self.groups.insert(t, PollGroup { token: t });
        self.next_token = if t == i32::MAX { 1 } else { t + 1 };
        Ok(t)
    }

    /// Destroy a poll group by token. Returns `Ok(())` if removed, or
    /// `Err(())` if the token was not found.
    pub fn destroy(&mut self, token: PollGroupToken) -> Result<(), ()> {
        self.groups.remove(&token).map(|_| ()).ok_or(())
    }

    /// Check whether `token` names a live group in this table.
    pub fn contains(&self, token: PollGroupToken) -> bool {
        self.groups.contains_key(&token)
    }

    /// Number of live groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Clear all groups (used on execve to revoke tokens).
    pub fn clear(&mut self) {
        self.groups.clear();
    }
}

/// The extended `pollfd` struct for `sys_poll_deadline`. 16 bytes per RFC 0003.
///
/// Layout: `fd` (4) + `events` (2) + `revents` (2) + `_pad` (2) +
/// `_pad2` (2) + `deferral_ns` (4) = 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PollFdDeadline {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
    pub _pad: u16,
    pub _pad2: u16,
    /// Max wake-defer window in nanoseconds. 0 = "wake me immediately"
    /// (classic poll). Nonzero = "you may defer my wake by up to N ns
    /// past readiness if you're batching". Hard cap: `DAPRA_MAX_DEFER_NS`.
    pub deferral_ns: u32,
}

// RFC 0003 mandates this size assertion.
const _: () = assert!(core::mem::size_of::<PollFdDeadline>() == 16);

/// Mask of revents that must never be deferred — immediate wake required.
/// POLLERR | POLLHUP | POLLNVAL per RFC 0003 §"Deferral-exempt wakes".
pub const DEFERRAL_EXEMPT_MASK: u16 = super::POLLERR | super::POLLHUP | super::POLLNVAL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pollfd_deadline_is_16_bytes() {
        assert_eq!(core::mem::size_of::<PollFdDeadline>(), 16);
    }

    #[test]
    fn dapra_max_defer_ns_is_10ms() {
        assert_eq!(DAPRA_MAX_DEFER_NS, 10_000_000);
    }

    #[test]
    fn poll_group_table_create_returns_positive_token() {
        let mut t = PollGroupTable::new();
        let tok = t.create().unwrap();
        assert!(tok > 0);
        assert_eq!(t.len(), 1);
        assert!(t.contains(tok));
    }

    #[test]
    fn poll_group_table_destroy_removes_group() {
        let mut t = PollGroupTable::new();
        let tok = t.create().unwrap();
        assert!(t.destroy(tok).is_ok());
        assert_eq!(t.len(), 0);
        assert!(!t.contains(tok));
    }

    #[test]
    fn poll_group_table_destroy_unknown_is_err() {
        let mut t = PollGroupTable::new();
        assert!(t.destroy(42).is_err());
    }

    #[test]
    fn poll_group_table_enforces_cap() {
        let mut t = PollGroupTable::new();
        for _ in 0..POLL_GROUP_MAX {
            assert!(t.create().is_ok());
        }
        assert!(t.create().is_err(), "must reject beyond POLL_GROUP_MAX");
    }

    #[test]
    fn poll_group_table_tokens_are_unique() {
        let mut t = PollGroupTable::new();
        let mut tokens = alloc::vec::Vec::new();
        for _ in 0..POLL_GROUP_MAX {
            tokens.push(t.create().unwrap());
        }
        // All tokens must be distinct.
        tokens.sort();
        tokens.dedup();
        assert_eq!(tokens.len(), POLL_GROUP_MAX);
    }

    #[test]
    fn poll_group_table_clear_revokes_all() {
        let mut t = PollGroupTable::new();
        let tok1 = t.create().unwrap();
        let tok2 = t.create().unwrap();
        t.clear();
        assert_eq!(t.len(), 0);
        assert!(!t.contains(tok1));
        assert!(!t.contains(tok2));
    }

    #[test]
    fn poll_group_table_reuse_after_destroy() {
        let mut t = PollGroupTable::new();
        let tok1 = t.create().unwrap();
        t.destroy(tok1).unwrap();
        let tok2 = t.create().unwrap();
        assert!(tok2 > 0);
        assert!(t.contains(tok2));
    }

    #[test]
    fn deferral_exempt_mask_has_correct_bits() {
        assert_ne!(DEFERRAL_EXEMPT_MASK & super::super::POLLERR, 0);
        assert_ne!(DEFERRAL_EXEMPT_MASK & super::super::POLLHUP, 0);
        assert_ne!(DEFERRAL_EXEMPT_MASK & super::super::POLLNVAL, 0);
        // POLLIN should NOT be exempt.
        assert_eq!(DEFERRAL_EXEMPT_MASK & super::super::POLLIN, 0);
    }

    #[test]
    fn pollfd_deadline_default_zero_deferral() {
        let pfd = PollFdDeadline::default();
        assert_eq!(pfd.deferral_ns, 0);
        assert_eq!(pfd.fd, 0);
        assert_eq!(pfd.events, 0);
        assert_eq!(pfd.revents, 0);
    }
}
