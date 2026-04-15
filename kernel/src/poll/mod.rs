//! Poll primitives — readiness masks, the two-pass `PollTable`, and the
//! `WaitQueue` that backs level-triggered readiness.
//!
//! RFC 0003 (`docs/RFC/0003-pipes-poll-tty.md` §"Poll table", §"Wake-queue
//! entry lifetime", §"Wait-latching invariant") defines a two-pass
//! `sys_poll`:
//!
//! - **Probe** pass — each `FileBackend::poll` reads readiness *without*
//!   registering on any `WaitQueue`. `PollTable::register` is a no-op.
//! - **Wait** pass — if nothing was ready, the table is rebuilt in Wait
//!   mode; each backend's `poll` now registers a [`PollEntry`] on its
//!   `WaitQueue` before the task parks. A concurrent `wake_poll_then_one`
//!   fires every registered poll-entry and exactly one blocking waiter.
//!
//! This module provides the primitives that live underneath `sys_poll`
//! and the backends (pipes, TTY, sockets) that implement waitability.
//! `sys_poll` itself lands in a later issue (#371); pipe and TTY backend
//! call sites land with #370 / #374.
//!
//! # Wake-queue entry lifetime
//!
//! Every [`PollEntry`] holds an `Arc<WaitQueue>`, never a raw pointer.
//! The [`PollTable`] drops its `PollEntry` vec on scope exit, which calls
//! [`WaitQueue::cancel`] for each entry under the queue's IRQ-safe lock.
//! Cancel is keyed on a monotonic [`WaitToken`], not a pointer, so an
//! entry de-queued concurrently by `wake_poll_then_one` is safe against
//! ABA on slot reuse. The Arc keeps the queue alive across the cancel,
//! closing the close-during-poll UAF.
//!
//! # Wait-latching invariant
//!
//! `register_wait` enqueues the current task id on the queue's blocking
//! waiter list under the queue's IRQ-safe lock. The caller then drops
//! its data locks and calls `task::block_current()`. If a concurrent
//! `wake_poll_then_one` (or `wake_all`) fires between `register_wait`
//! and `block_current`, it pops the waiter and calls `task::wake`, which
//! sets `wake_pending`. The task's `block_current` sees `wake_pending`
//! and returns immediately — the wake is never dropped on the floor.
//! This mirrors the protocol in `sync::WaitQueue`.

#[cfg(target_os = "none")]
use crate::sync::irqlock::IrqLock;
#[cfg(any(test, target_os = "none"))]
use alloc::collections::VecDeque;
#[cfg(any(test, target_os = "none"))]
use alloc::sync::Arc;
#[cfg(any(test, target_os = "none"))]
use alloc::vec::Vec;

// Host tests can't use IrqLock (it touches RFLAGS.IF) — fall back to a
// plain spin mutex, which has the same external API for our purposes.
#[cfg(all(test, not(target_os = "none")))]
use spin::Mutex as IrqLock;

/// Readiness bitmask. Matches Linux's `revents` width (`short`, 16 bits).
pub type PollMask = u16;

/// Normal data available to read (matches Linux `POLLIN`).
pub const POLLIN: PollMask = 0x0001;
/// Priority data available (matches Linux `POLLPRI`).
pub const POLLPRI: PollMask = 0x0002;
/// Normal data can be written without blocking (matches Linux `POLLOUT`).
pub const POLLOUT: PollMask = 0x0004;
/// Error condition (always reported if set, even if not requested).
pub const POLLERR: PollMask = 0x0008;
/// Peer closed its end (always reported if set, even if not requested).
pub const POLLHUP: PollMask = 0x0010;
/// Invalid request (fd not open; always reported if set).
pub const POLLNVAL: PollMask = 0x0020;
/// Normal-priority data available (synonym of `POLLIN` on Linux).
pub const POLLRDNORM: PollMask = 0x0040;
/// Normal-priority data can be written (synonym of `POLLOUT` on Linux).
pub const POLLWRNORM: PollMask = 0x0100;

/// Advertised readiness for a backend that has not overridden `poll`.
///
/// Matches Linux's `DEFAULT_POLLMASK` (`fs/select.c`): read/write both
/// ready, no error, no hangup. Degrades to spurious wakeups rather than
/// missed ones.
pub const DEFAULT_POLLMASK: PollMask = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

/// Two modes of the `sys_poll` scan.
#[cfg(any(test, target_os = "none"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollMode {
    /// First pass: drivers report readiness; `register` is a no-op.
    Probe,
    /// Second pass: drivers register `PollEntry` records before parking.
    Wait,
}

/// Opaque handle returned by `WaitQueue::register_poll` and
/// `register_wait`. Used to cancel a registration or de-duplicate re-registers.
///
/// Tokens are minted from a per-queue monotonic `u64` counter under the
/// queue's inner lock, so they are never reused within a single queue's
/// lifetime — an entry cancelled after its slot is freed cannot be confused
/// with a later registrant occupying that slot (no ABA).
#[cfg(any(test, target_os = "none"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitToken(u64);

/// Per-syscall scratch tracking poll registrations.
///
/// `PollTable` is owned by the `sys_poll` body (one per syscall invocation).
/// It keeps `Arc<WaitQueue>`s alive for the duration of the scan so that a
/// backend closing its fd concurrently cannot free the queue under us, and
/// it runs `cancel_all` on drop so no stale entries linger past the syscall.
#[cfg(any(test, target_os = "none"))]
pub struct PollTable {
    mode: PollMode,
    /// Task to wake when any registered queue fires. Only meaningful in Wait
    /// mode — `probe()` sets this to a sentinel it never hands out.
    wake_tid: usize,
    entries: Vec<PollEntry>,
}

/// A single registration: "this PollTable is interested in this WaitQueue."
///
/// Holds `Arc<WaitQueue>` (not a raw pointer) per RFC 0003 §Wake-queue entry
/// lifetime. Cancellation is idempotent and safe even if the queue has
/// already fired. The `wake_tid` identifies the sys_poll task to resume when
/// the queue fires a `wake_*` — stored at registration time and handed to
/// `WaitQueue::register_poll` so it lands on the queue's poller record.
#[cfg(any(test, target_os = "none"))]
pub(crate) struct PollEntry {
    queue: Arc<WaitQueue>,
    token: WaitToken,
}

#[cfg(any(test, target_os = "none"))]
impl PollTable {
    /// Construct a probe-mode table. `register` is a no-op in this mode, so
    /// no `wake_tid` is needed.
    pub const fn probe() -> Self {
        Self {
            mode: PollMode::Probe,
            wake_tid: 0,
            entries: Vec::new(),
        }
    }

    /// Construct a wait-mode table bound to the task that will park after
    /// the scan. `register` enqueues `PollEntry`s whose poll-side wake targets
    /// resolve to `wake_tid` — on any `wake_*`, that task is resumed.
    pub const fn wait(wake_tid: usize) -> Self {
        Self {
            mode: PollMode::Wait,
            wake_tid,
            entries: Vec::new(),
        }
    }

    /// Current mode.
    pub fn mode(&self) -> PollMode {
        self.mode
    }

    /// Register interest in `queue`'s readiness.
    ///
    /// - In Probe mode: no-op.
    /// - In Wait mode: atomically mints a `WaitToken`, pushes it onto
    ///   `queue`'s poll list, and stores the resulting `PollEntry` on this
    ///   table. Duplicate `(queue, self)` pairs are de-duped by Arc identity
    ///   so a backend whose `poll` fires twice within one scan doesn't
    ///   accumulate duplicate wake targets.
    pub fn register(&mut self, queue: &Arc<WaitQueue>) {
        if self.mode == PollMode::Probe {
            return;
        }
        if self.entries.iter().any(|e| Arc::ptr_eq(&e.queue, queue)) {
            return;
        }
        let token = queue.register_poll(self.wake_tid);
        self.entries.push(PollEntry {
            queue: queue.clone(),
            token,
        });
    }

    /// Number of active registrations (for tests and diagnostics).
    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Cancel every registration on this table. Idempotent.
    fn cancel_all(&mut self) {
        for entry in self.entries.drain(..) {
            entry.queue.cancel(entry.token);
        }
    }
}

#[cfg(any(test, target_os = "none"))]
impl Drop for PollTable {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

#[cfg(any(test, target_os = "none"))]
struct WaitQueueInner {
    /// `(token, wake_tid)` pairs for passive poll registrations — every
    /// `wake_*` fires `task::wake(wake_tid)` for each entry so the sleeping
    /// `sys_poll` task resumes.
    pollers: VecDeque<(WaitToken, usize)>,
    /// `(token, tid)` pairs for blocking waiters — woken one-at-a-time
    /// by `wake_poll_then_one`, or all by `wake_all`.
    waiters: VecDeque<(WaitToken, usize)>,
    /// Monotonic token source. `u64` is wide enough that wrap-around is
    /// not a practical concern within a queue's lifetime.
    next_token: u64,
}

/// Poll-aware wait queue.
///
/// Combines two lists under one IRQ-safe lock: a **poll list** of passive
/// registrations from `sys_poll` (each fires once on any wake) and a
/// **waiter list** of blocking tasks parked on `register_wait` +
/// `block_current`.
///
/// Callable from ISR context because the inner lock is an [`IrqLock`].
/// Do not hold any other lock across `wake_poll_then_one` / `wake_all`.
///
/// # Typical usage
///
/// ```ignore
/// // --- in a FileBackend::poll override ---
/// fn poll(&self, pt: &mut PollTable) -> PollMask {
///     pt.register(&self.waitq);   // Wait-mode only; Probe is a no-op
///     self.readiness()            // bitmask recomputed every call
/// }
///
/// // --- in a blocking read ---
/// let tok = self.waitq.register_wait(task::current_id());
/// if !self.has_data() {
///     task::block_current();      // wait-latching via wake_pending
/// }
/// self.waitq.cancel(tok);         // drain any late wake
///
/// // --- in a producer that just published data ---
/// self.waitq.wake_poll_then_one();
/// ```
#[cfg(any(test, target_os = "none"))]
pub struct WaitQueue {
    inner: IrqLock<WaitQueueInner>,
}

#[cfg(any(test, target_os = "none"))]
impl WaitQueue {
    /// Create an empty queue. Allocates — requires `alloc`.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: IrqLock::new(WaitQueueInner {
                pollers: VecDeque::new(),
                waiters: VecDeque::new(),
                next_token: 0,
            }),
        })
    }

    /// Mint a new monotonic token. Held under the inner lock so mint +
    /// push is a single critical section.
    fn mint_token(inner: &mut WaitQueueInner) -> WaitToken {
        let id = inner.next_token;
        inner.next_token = inner.next_token.wrapping_add(1);
        WaitToken(id)
    }

    /// Register a passive poll interest. Called by `PollTable::register`
    /// in Wait mode.
    ///
    /// `wake_tid` is the task that a later `wake_*` on this queue should
    /// resume — typically the `sys_poll` caller that built the `PollTable`.
    /// The returned `WaitToken` is remembered by the `PollTable` and
    /// passed to `cancel` when the table is dropped. Production callers
    /// should use `PollTable` rather than calling this directly.
    pub(crate) fn register_poll(&self, wake_tid: usize) -> WaitToken {
        let mut inner = self.inner.lock();
        let token = Self::mint_token(&mut inner);
        inner.pollers.push_back((token, wake_tid));
        token
    }

    /// Register a blocking waiter.
    ///
    /// The caller **must** call `task::block_current()` (or equivalent)
    /// after this returns, and **must** call `cancel(tok)` after waking
    /// to drain any stale entry left by a `wake_pending`-path wake.
    /// Returns a token that keys the later cancel.
    pub fn register_wait(&self, tid: usize) -> WaitToken {
        let mut inner = self.inner.lock();
        let token = Self::mint_token(&mut inner);
        inner.waiters.push_back((token, tid));
        token
    }

    /// Remove a registration keyed by `token`. Looks in both lists.
    /// Idempotent: cancelling an already-fired token is a cheap miss.
    pub fn cancel(&self, token: WaitToken) {
        let mut inner = self.inner.lock();
        if let Some(pos) = inner.pollers.iter().position(|&(t, _)| t == token) {
            inner.pollers.remove(pos);
            return;
        }
        if let Some(pos) = inner.waiters.iter().position(|&(t, _)| t == token) {
            inner.waiters.remove(pos);
        }
    }

    /// Fire every poller plus at most one blocking waiter.
    ///
    /// Semantics per RFC 0003: poll-side registrations are level-triggered,
    /// so they're always drained on any readiness change. The waiter side
    /// is one-shot-per-event because blocking readers consume the resource
    /// (e.g. a pipe byte) and only one can make progress at a time.
    pub fn wake_poll_then_one(&self) {
        // Drain lists under the lock, then call into task::wake outside
        // it — task::wake touches the scheduler's own locks and must not
        // be called while ours is held.
        let pollers;
        let woken_waiter;
        {
            let mut inner = self.inner.lock();
            pollers = core::mem::take(&mut inner.pollers);
            woken_waiter = inner.waiters.pop_front();
        }
        for (_tok, tid) in pollers {
            task_wake(tid);
        }
        if let Some((_tok, tid)) = woken_waiter {
            task_wake(tid);
        }
    }

    /// Fire every poller and every blocking waiter.
    ///
    /// Used on HUP / error conditions where every parked reader and every
    /// polling selector must observe the state change.
    pub fn wake_all(&self) {
        let pollers;
        let waiters;
        {
            let mut inner = self.inner.lock();
            pollers = core::mem::take(&mut inner.pollers);
            waiters = core::mem::take(&mut inner.waiters);
        }
        for (_tok, tid) in pollers {
            task_wake(tid);
        }
        for (_tok, tid) in waiters {
            task_wake(tid);
        }
    }

    /// `(poll_count, waiter_count)` — test-harness synchronisation.
    ///
    /// Not appropriate for production logic: the counts can change the
    /// instant they're returned.
    #[cfg(test)]
    pub fn counts(&self) -> (usize, usize) {
        let inner = self.inner.lock();
        (inner.pollers.len(), inner.waiters.len())
    }
}

/// Wake helper. On the kernel, hands off to `task::wake`. On host tests,
/// wake is a no-op — tests assert on queue invariants, not scheduler state.
#[cfg(target_os = "none")]
fn task_wake(tid: usize) {
    crate::task::wake(tid);
}

#[cfg(all(test, not(target_os = "none")))]
fn task_wake(tid: usize) {
    // Host-side: no scheduler. Record into a test-visible log so tests can
    // assert that `wake_*` invoked the stored wake target for each entry.
    test_wake_log::record(tid);
}

#[cfg(all(test, not(target_os = "none")))]
mod test_wake_log {
    use alloc::vec::Vec;
    use core::cell::RefCell;

    // Thread-local so parallel test threads each get their own log and
    // can't clobber each other's drain() calls (CodeRabbit #392).
    thread_local! {
        static WAKES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(tid: usize) {
        WAKES.with(|v| v.borrow_mut().push(tid));
    }

    pub(super) fn drain() -> Vec<usize> {
        WAKES.with(|v| core::mem::take(&mut *v.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pollmask_has_expected_bits() {
        assert_eq!(DEFAULT_POLLMASK, POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM);
    }

    #[test]
    fn pollmask_bit_values_match_linux() {
        // Pinned against the Linux x86_64 numeric values from
        // <asm-generic/poll.h>. Same ABI discipline as the O_* flags in
        // `fs/mod.rs`: any drift breaks the `sys_poll` syscall ABI.
        assert_eq!(POLLIN, 0x0001);
        assert_eq!(POLLPRI, 0x0002);
        assert_eq!(POLLOUT, 0x0004);
        assert_eq!(POLLERR, 0x0008);
        assert_eq!(POLLHUP, 0x0010);
        assert_eq!(POLLNVAL, 0x0020);
        assert_eq!(POLLRDNORM, 0x0040);
        assert_eq!(POLLWRNORM, 0x0100);
    }

    #[test]
    fn probe_mode_register_is_noop() {
        let wq = WaitQueue::new();
        let mut pt = PollTable::probe();
        pt.register(&wq);
        pt.register(&wq);
        assert_eq!(pt.entry_count(), 0);
        assert_eq!(wq.counts(), (0, 0));
    }

    #[test]
    fn wait_mode_register_enqueues() {
        let wq = WaitQueue::new();
        let mut pt = PollTable::wait(7);
        pt.register(&wq);
        assert_eq!(pt.entry_count(), 1);
        assert_eq!(wq.counts(), (1, 0));
    }

    #[test]
    fn wait_mode_register_dedups_same_queue() {
        let wq = WaitQueue::new();
        let mut pt = PollTable::wait(7);
        pt.register(&wq);
        pt.register(&wq);
        pt.register(&wq);
        assert_eq!(pt.entry_count(), 1);
        assert_eq!(wq.counts(), (1, 0));
    }

    #[test]
    fn drop_polltable_cancels_registrations() {
        let wq = WaitQueue::new();
        {
            let mut pt = PollTable::wait(7);
            pt.register(&wq);
            assert_eq!(wq.counts(), (1, 0));
        }
        assert_eq!(wq.counts(), (0, 0), "cancel_all must drain pollers");
    }

    #[test]
    fn wake_all_drains_pollers_and_waiters() {
        let _ = test_wake_log::drain();
        let wq = WaitQueue::new();
        let mut pt = PollTable::wait(17);
        pt.register(&wq);
        let _w = wq.register_wait(42);
        assert_eq!(wq.counts(), (1, 1));
        wq.wake_all();
        assert_eq!(wq.counts(), (0, 0));
        let wakes = test_wake_log::drain();
        assert!(wakes.contains(&17), "poller's wake target must fire");
        assert!(wakes.contains(&42), "blocking waiter's tid must fire");
    }

    #[test]
    fn wake_poll_then_one_fires_every_poller_wake_target() {
        // Covers CodeRabbit's #392 finding: a readiness transition must
        // resume every sleeping sys_poll task registered on the queue.
        let _ = test_wake_log::drain();
        let wq = WaitQueue::new();
        let mut pt_a = PollTable::wait(100);
        let mut pt_b = PollTable::wait(200);
        pt_a.register(&wq);
        pt_b.register(&wq);
        let _w = wq.register_wait(300);

        wq.wake_poll_then_one();

        let wakes = test_wake_log::drain();
        assert!(wakes.contains(&100), "pt_a's wake target must fire");
        assert!(wakes.contains(&200), "pt_b's wake target must fire");
        assert!(wakes.contains(&300), "blocking waiter must also fire");

        // Keep tables alive so their Drop cancel_all runs after the
        // assertions.
        drop(pt_a);
        drop(pt_b);
    }

    #[test]
    fn wake_poll_then_one_drains_pollers_and_pops_one_waiter() {
        let wq = WaitQueue::new();
        let mut pt1 = PollTable::wait(7);
        let mut pt2 = PollTable::wait(8);
        pt1.register(&wq);
        // Second distinct table to get a second poller entry.
        pt2.register(&wq);
        let _w1 = wq.register_wait(1);
        let _w2 = wq.register_wait(2);
        assert_eq!(wq.counts(), (2, 2));

        wq.wake_poll_then_one();
        assert_eq!(wq.counts(), (0, 1), "all pollers, exactly one waiter");

        wq.wake_poll_then_one();
        assert_eq!(wq.counts(), (0, 0), "second call wakes the last waiter");

        // Keep the PollTables alive until after the assertions so their
        // Drop cancellations don't fire mid-test.
        drop(pt1);
        drop(pt2);
    }

    #[test]
    fn drop_before_wake_no_uaf() {
        // The dangerous path: register, drop the table (runs cancel_all),
        // then wake. With Arc<WaitQueue> and token-keyed cancel the wake
        // finds an empty list and returns cleanly.
        let wq = WaitQueue::new();
        {
            let mut pt = PollTable::wait(7);
            pt.register(&wq);
        }
        wq.wake_poll_then_one();
        wq.wake_all();
        assert_eq!(wq.counts(), (0, 0));
    }

    #[test]
    fn cancel_is_idempotent() {
        let wq = WaitQueue::new();
        let tok = wq.register_poll(7);
        wq.cancel(tok);
        wq.cancel(tok);
        // Cancel an unknown token.
        wq.cancel(WaitToken(u64::MAX));
        assert_eq!(wq.counts(), (0, 0));
    }

    #[test]
    fn token_monotonic_no_aba() {
        let wq = WaitQueue::new();
        let t0 = wq.register_poll(7);
        wq.cancel(t0);
        let t1 = wq.register_poll(7);
        wq.cancel(t1);
        let t2 = wq.register_poll(7);
        wq.cancel(t2);
        assert_ne!(t0, t1);
        assert_ne!(t1, t2);
        assert_ne!(t0, t2);
    }

    #[test]
    fn wake_all_with_no_waiters_is_noop() {
        let wq = WaitQueue::new();
        wq.wake_all();
        wq.wake_poll_then_one();
        assert_eq!(wq.counts(), (0, 0));
    }
}
