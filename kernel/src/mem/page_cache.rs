//! Per-inode page cache (RFC 0007).
//!
//! This module lands the foundation data structures for the file-backed
//! page cache: a per-inode index of cached file pages, the per-page
//! state machine that synchronises fillers / observers / writeback /
//! truncation, and the split-lock discipline that keeps the index
//! mutex out of every long-running I/O critical section.
//!
//! Out of scope here (tracked under sibling issues, see RFC 0007
//! Workstream A roadmap):
//!
//! - `FileObject` and the `VmObject` integration (#738).
//! - The page-fault path wiring (#739).
//! - Eviction and the writeback-completion waitqueue (#740).
//!
//! ## Read-ahead heuristic (#741)
//!
//! [`PageCache`] now carries the per-inode `ra_state`
//! ([`PageCacheInner::ra`]) described in RFC 0007 §Performance
//! Considerations (readahead). The state is a tiny exponential-ramp
//! tracker keyed on the streak of sequentially-adjacent misses:
//!
//! - On a fresh inode the read-ahead window is **0 pages**. RFC 0007
//!   blocking-finding *Performance B2* — an unconditional 8-page
//!   read-ahead would *increase* cold-execve latency, since the
//!   execve fault stream is rarely sequential past the first few
//!   pages.
//! - [`PageCache::note_miss`] is the single entry point the page-fault
//!   slow path calls when it has just lost the install race or
//!   otherwise observes a miss at `pgoff`. It returns the number of
//!   *additional* read-ahead pages the FS should issue past `pgoff`,
//!   based on the streak observed so far. The cache itself still does
//!   not invoke `ops.readahead` — that wiring is part of #739/#752.
//! - Sequential streak detection: if `pgoff == ra.last_pgoff + 1`,
//!   `hit_streak` is incremented; once `hit_streak >= 2`, the next
//!   miss's read-ahead window is `min(2^hit_streak, RA_MAX_PAGES)`.
//!   Any non-sequential miss resets `hit_streak` to 1 and the window
//!   to 0.
//! - `posix_fadvise(POSIX_FADV_SEQUENTIAL)` and `madvise(MADV_SEQUENTIAL)`
//!   set the cache's [`RaMode::Sequential`] mode, which jumps the
//!   read-ahead window straight to [`RA_MAX_PAGES`] without waiting
//!   for a streak. Their `RANDOM` equivalents ([`RaMode::Random`])
//!   permanently disable read-ahead for the inode until the mode is
//!   reset to [`RaMode::Normal`]. See [`PageCache::set_ra_mode`].
//!
//! The actual issuance of read-ahead I/O lives in the FS-specific
//! `AddressSpaceOps::readahead` impl (default is a no-op; ext2's
//! impl is #752).
//!
//! What this PR establishes is therefore a deliberately narrow
//! foundation:
//!
//! 1. The [`CachePage`] type with its [`PG_UPTODATE`], [`PG_DIRTY`],
//!    [`PG_IN_FLIGHT`], [`PG_WRITEBACK`], [`PG_LOCKED`] state bits.
//!    All transitions that have cross-thread visibility obligations
//!    are documented and implemented to the Acquire/Release pairing
//!    described in RFC 0007 §State-bit ordering.
//! 2. [`PageCache`] / [`PageCacheInner`] with the level-4 per-inode
//!    `BlockingMutex` of RFC 0007 §Lock-order ladder. The index
//!    mutex is *separate* from the per-page atomics: the cache
//!    reader-fast-path lookup takes the mutex only long enough to
//!    `Arc::clone` the [`CachePage`] entry, then drops it before any
//!    blocking work.
//! 3. The install-race protocol: [`PageCache::install_or_get`] is the
//!    one routine that decides whether the calling task wins the
//!    fill (returns a freshly allocated stub with [`PG_LOCKED`] set
//!    and [`PG_UPTODATE`] clear) or loses (returns the
//!    already-installed entry whose filler may still be running).
//!    The loser parks on [`CachePage::wait`] via
//!    [`CachePage::wait_until_unlocked`].
//! 4. The filler-error contract: [`PageCache::abandon_locked_stub`]
//!    removes a failed stub from the index, clears `PG_LOCKED`, and
//!    wakes every waiter so they retry against a fresh stub. This
//!    is the path RFC 0007 §State-bit ordering "Filler error
//!    handling" describes.
//!
//! The choice to keep the index mutex separate from per-page atomics
//! is the split-lock discipline of RFC 0007 §Split-lock discipline:
//! cache lookups and waitqueue parking each take their own
//! independent locks, so a slow `readpage` cannot hold the per-inode
//! cache mutex against another task's lookup of an unrelated page.
//!
//! [`PageCache`] now carries the `Arc<dyn AddressSpaceOps>` per-FS
//! hook captured at construction (#737). The cache itself does not
//! yet *invoke* `readpage` / `writepage` — that wiring is the
//! page-fault and writeback-daemon work in #739/#740/#742. Until
//! those land, host unit tests construct a `PageCache` against a
//! stub ops impl (see `mem::aops::tests::MemoryBackedOps`) and
//! exercise the install-race / state-bit-ordering / filler-error
//! protocols against it.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;

use spin::Once;

use crate::mem::aops::AddressSpaceOps;

// Sync primitives.
//
// On bare metal we use the real `BlockingMutex` / `WaitQueue` — they
// sleep on contention and ride through the scheduler exactly as RFC
// 0007 specifies for the level-4 lock and per-page park.
//
// On host (`cfg(test)`) the `crate::sync` module is gated out (it
// pulls in `task::block_current` / `task::wake`, which are kernel-only).
// We substitute `spin::Mutex` for `BlockingMutex` and a minimal local
// stand-in for `WaitQueue`. The stand-in is a no-op park / wake — host
// tests of the install-race protocol exercise the `Arc` and atomic
// state-bit transitions; they never actually block on a waitqueue, so
// the no-op shape is faithful.
#[cfg(target_os = "none")]
use crate::sync::{BlockingMutex, WaitQueue};

#[cfg(all(test, not(target_os = "none")))]
use host_stub::{BlockingMutex, WaitQueue};

#[cfg(all(test, not(target_os = "none")))]
mod host_stub {
    //! Host-only stand-ins for the bare-metal sync primitives. Kept
    //! intentionally minimal — host unit tests do not exercise
    //! cross-thread parking; they only need a `Mutex` wrapper that
    //! matches the `BlockingMutex` API (`new`, `lock`) and a
    //! `WaitQueue` whose construction and `notify_*` calls are
    //! no-ops.
    use spin::Mutex as InnerMutex;

    pub struct BlockingMutex<T: ?Sized>(InnerMutex<T>);

    impl<T> BlockingMutex<T> {
        pub fn new(value: T) -> Self {
            Self(InnerMutex::new(value))
        }
    }

    impl<T: ?Sized> BlockingMutex<T> {
        pub fn lock(&self) -> spin::MutexGuard<'_, T> {
            self.0.lock()
        }

        /// Non-blocking acquisition. Returns `None` if the lock is
        /// currently held. Used by the host-only lock-order tests
        /// (RFC 0007 §Lock-order ladder, split-lock discipline) to
        /// probe whether a `cache.inner` guard has leaked across a
        /// slow-path I/O wait — a `None` here would deadlock on
        /// bare metal, so the host probe surfaces the violation as
        /// a test failure instead.
        pub fn try_lock(&self) -> Option<spin::MutexGuard<'_, T>> {
            self.0.try_lock()
        }
    }

    /// Host stand-in for [`crate::sync::WaitQueue`].
    ///
    /// `notify_all` does not actually wake any task (host tests don't
    /// run under the kernel scheduler), but it bumps an internal
    /// counter so issue #757's host tests can verify that
    /// `CachePage::end_writeback` and `CachePage::Drop` *do* fire the
    /// wake — even though the wake itself has no observable effect on
    /// host because there is no parked task to wake.
    pub struct WaitQueue {
        notify_count: core::sync::atomic::AtomicU64,
    }

    impl WaitQueue {
        pub const fn new() -> Self {
            Self {
                notify_count: core::sync::atomic::AtomicU64::new(0),
            }
        }
        pub fn notify_all(&self) {
            self.notify_count
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        /// Number of times `notify_all` has fired against this queue.
        /// Test-only; the bare-metal queue does not expose a
        /// notification counter.
        #[allow(dead_code)]
        pub fn notify_count(&self) -> u64 {
            self.notify_count
                .load(core::sync::atomic::Ordering::Relaxed)
        }
        /// Host stand-in for the bare-metal park loop. Returns
        /// immediately; host unit tests do not cross-thread block on
        /// `PG_LOCKED`. If a future host test does need to exercise
        /// the predicate, it can call `wait_while` and observe that
        /// `cond` is invoked exactly once.
        pub fn wait_while<F: FnMut() -> bool>(&self, mut cond: F) {
            // Single check; do not loop. Bare-metal `wait_while` parks
            // on the queue and re-checks after wake; the host stub
            // intentionally collapses the loop to a no-op so tests
            // that *don't* rely on actually blocking still observe
            // the predicate being called.
            let _ = cond();
        }
    }
}

// --- State bits (`PG_*`) ------------------------------------------------

/// Page contents reflect the on-disk image. Set by the filler with
/// `Release` ordering; observed by readers with `Acquire`.
pub const PG_UPTODATE: u8 = 1 << 0;

/// Page has been mutated since the last writeback. Set by the
/// MAP_SHARED write fault under [`PageCacheInner`] index lock so
/// the writeback daemon's snapshot never sees a `PG_DIRTY`-set,
/// dirty-index-unenrolled page (RFC 0007 §State-bit ordering, writer
/// side).
pub const PG_DIRTY: u8 = 1 << 1;

/// I/O is presently in flight against this page. Distinct from
/// [`PG_LOCKED`] because the locked-fill handshake may block on a
/// waitqueue *before* I/O is actually issued (e.g. parked on a
/// buffer-cache eviction wait); this bit advertises the active
/// `readpage` so other tasks know to park rather than spin.
pub const PG_IN_FLIGHT: u8 = 1 << 2;

/// Writeback (`writepage`) is in progress; do not re-dirty.
/// Truncation parks on [`CachePage::wait`] while this bit is set.
pub const PG_WRITEBACK: u8 = 1 << 3;

/// Exclusive serialisation for cache-fill. Held by the task that won
/// the install race; released with `Release` ordering once
/// [`PG_UPTODATE`] is set (or once the stub is being abandoned via
/// [`PageCache::abandon_locked_stub`]).
pub const PG_LOCKED: u8 = 1 << 4;

// --- Inode identity -----------------------------------------------------

/// Identity of an inode within a mounted filesystem. Page caches are
/// per-inode and never rebound, so the identity is captured at
/// construction and stored verbatim for writeback enqueue.
///
/// `(fs_id, ino)` matches the identity discipline used by the VFS
/// inode table (`fs/vfs/inode.rs` module doc).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InodeId {
    /// Identifier of the mounted superblock that owns the inode.
    pub fs_id: u64,
    /// Per-superblock inode number.
    pub ino: u64,
}

impl InodeId {
    pub const fn new(fs_id: u64, ino: u64) -> Self {
        Self { fs_id, ino }
    }
}

// --- CachePage ----------------------------------------------------------

/// One page-sized cache entry.
///
/// Padded to 64 bytes so that adjacent `CachePage`s (laid out via
/// `Arc<CachePage>` in a [`BTreeMap`]) do not false-share their
/// [`AtomicU8`] state bytes on SMP. vibix is currently uniprocessor;
/// the alignment is a forward-compat invariant — RFC 0007 §`CachePage`
/// makes the alignment normative so an SMP enable doesn't have to
/// chase down false-sharing regressions later.
///
/// All cross-thread state is in `state` and `wait`. The `phys` and
/// `pgoff` fields are immutable for the lifetime of the entry: the
/// physical frame is allocated when the stub is constructed and
/// reclaimed when the [`Arc`] drops to zero (frame-free is wired up
/// in #740 once eviction lands; today the stub is stable from
/// install-time onwards).
#[repr(align(64))]
pub struct CachePage {
    /// Physical frame containing the cached file data. Refcounted by
    /// the existing `mem::refcount` machinery for PTE-mapping; the
    /// cache itself holds exactly one frame reference for as long as
    /// the [`Arc<CachePage>`] is alive in the index.
    pub phys: u64,

    /// Page index = file offset / 4 KiB.
    pub pgoff: u64,

    /// State bits — see the `PG_*` constants above.
    ///
    /// `pub(crate)` rather than `pub`: every cross-thread transition
    /// has a documented Acquire/Release ordering obligation, so
    /// out-of-crate callers must go through the helper methods on
    /// this type (which encode the orderings). Inside the crate we
    /// allow direct atomic operations because the call-sites are
    /// auditable in one place — but even in-crate, prefer the
    /// helpers; reach for the raw [`AtomicU8`] only inside this
    /// module and under the orderings documented at each call site.
    pub(crate) state: AtomicU8,

    /// Wait-queue for the LOCKED-fill and WRITEBACK handshakes. A
    /// second fault on the same page parks here until the original
    /// reader publishes [`PG_UPTODATE`]; `truncate_below` parks here
    /// on [`PG_WRITEBACK`] to wait out an in-flight `writepage` before
    /// the FS is allowed to free the underlying blocks.
    pub(crate) wait: WaitQueue,

    /// Owning [`PageCache`]'s `writeback_complete_wq`. Set exactly
    /// once when the stub is installed into a [`PageCache`] via
    /// [`PageCache::install_or_get`]; remains [`Once::get`] = `None`
    /// for free-standing stubs (e.g. host unit tests that exercise
    /// individual [`CachePage`] state transitions without ever
    /// installing into a cache).
    ///
    /// RFC 0007 §Eviction liveness: kicked from
    /// [`Self::end_writeback`] (the writeback-completion side) and
    /// from [`Drop`] (the strong-count-reaches-1 side, so that a page
    /// dropped without an explicit `end_writeback` still wakes
    /// direct-reclaim parkers — closes the lost-wakeup window when a
    /// `WritebackHandle` is dropped without `end_writeback`).
    pub(crate) parent_wb_wq: Once<Arc<WaitQueue>>,

    /// CLOCK-Pro reference bit. Set on every cache hit so the eviction
    /// sweep observes the access; cleared by the sweep when it demotes
    /// or promotes an entry. Mirrors `BufferHead::clock_ref` from
    /// `block::cache`.
    pub(crate) clock_ref: core::sync::atomic::AtomicBool,
}

impl CachePage {
    /// Construct a fresh stub with [`PG_LOCKED`] set. The caller is
    /// the filler and is responsible for either driving the fill to
    /// completion (`Release` ordering on [`PG_UPTODATE`] then on the
    /// `PG_LOCKED` clear) or abandoning the stub via
    /// [`PageCache::abandon_locked_stub`] on filler error.
    ///
    /// The freshly constructed page has `PG_LOCKED` set and every
    /// other bit clear. The `Acquire` on the install side (other
    /// tasks observing the entry) is implicit in the `Acquire` load
    /// they perform on `state` before reading `phys` / data.
    pub fn new_locked(phys: u64, pgoff: u64) -> Arc<Self> {
        Arc::new(Self {
            phys,
            pgoff,
            state: AtomicU8::new(PG_LOCKED),
            wait: WaitQueue::new(),
            parent_wb_wq: Once::new(),
            clock_ref: core::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Read the current state bits with `Acquire` ordering.
    ///
    /// `Acquire` is what synchronises-with the filler's `Release` on
    /// the `PG_LOCKED` clear: any observer that loads the state and
    /// sees `PG_LOCKED` clear is guaranteed to see the writes the
    /// filler performed *during* `readpage` (i.e. the page contents).
    #[inline]
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// `true` iff [`PG_UPTODATE`] is currently set.
    #[inline]
    pub fn is_uptodate(&self) -> bool {
        self.state() & PG_UPTODATE != 0
    }

    /// `true` iff [`PG_DIRTY`] is currently set.
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.state() & PG_DIRTY != 0
    }

    /// `true` iff [`PG_LOCKED`] is currently set.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.state() & PG_LOCKED != 0
    }

    /// `true` iff [`PG_IN_FLIGHT`] is currently set.
    #[inline]
    pub fn is_in_flight(&self) -> bool {
        self.state() & PG_IN_FLIGHT != 0
    }

    /// `true` iff [`PG_WRITEBACK`] is currently set.
    #[inline]
    pub fn is_writeback(&self) -> bool {
        self.state() & PG_WRITEBACK != 0
    }

    /// Mark `PG_IN_FLIGHT` while the filler issues a `readpage`. Uses
    /// `AcqRel` so the bit's appearance synchronises with whichever
    /// task observes it via [`state`](Self::state).
    pub fn mark_in_flight(&self) {
        self.state.fetch_or(PG_IN_FLIGHT, Ordering::AcqRel);
    }

    /// Clear `PG_IN_FLIGHT` once the readpage call returns (whether
    /// successfully or in error). Paired with the [`PG_LOCKED`] clear
    /// or the [`PG_UPTODATE`] publish, depending on outcome.
    pub fn clear_in_flight(&self) {
        self.state.fetch_and(!PG_IN_FLIGHT, Ordering::Release);
    }

    /// Filler-success publish: set [`PG_UPTODATE`] with `Release` and
    /// then clear [`PG_LOCKED`] with `Release`, finally waking every
    /// waiter parked on [`Self::wait`].
    ///
    /// The two writes are *both* `Release` — RFC 0007 §State-bit
    /// ordering: the `Release` on the `PG_LOCKED` clear is the one
    /// that a non-locking reader pairs against, and it must happen
    /// after the `PG_UPTODATE` set so any observer that sees
    /// `PG_LOCKED` clear also sees `PG_UPTODATE` set.
    ///
    /// The order also matters because once `PG_LOCKED` clears, other
    /// tasks may install PTEs against `phys`; they read the bytes
    /// the filler wrote during `readpage`. The `Acquire` load on the
    /// observer side is what makes those bytes visible.
    pub fn publish_uptodate_and_unlock(&self) {
        // Set UPTODATE first (Release).
        self.state.fetch_or(PG_UPTODATE, Ordering::Release);
        // Then clear LOCKED (Release). Observers that load state with
        // Acquire and see LOCKED clear are guaranteed to also see
        // UPTODATE set and the page bytes.
        self.state.fetch_and(!PG_LOCKED, Ordering::Release);
        // Wake every parked waiter; lost-wakeup safety comes from the
        // wait_while predicate re-checking `is_locked()` under the
        // queue lock.
        self.wait.notify_all();
    }

    /// Park the calling task until [`PG_LOCKED`] clears. The
    /// re-check is performed under the waitqueue's internal lock,
    /// so a `notify_all` from the filler that fired between our
    /// initial `is_locked()` test and the park is observed correctly
    /// (RFC 0007 §State-bit ordering, observer side; combined with
    /// [`WaitQueue`]'s lost-wakeup protocol).
    pub fn wait_until_unlocked(&self) {
        self.wait.wait_while(|| self.is_locked());
    }

    /// Park the calling task until [`PG_WRITEBACK`] clears. Symmetrical
    /// to [`Self::wait_until_unlocked`] but predicated on the
    /// writeback bit instead of the lock bit.
    ///
    /// This is the truncate-below park point: a shrinking truncate
    /// must not free the on-disk blocks underneath a page whose
    /// `writepage` is presently in flight (the daemon could otherwise
    /// commit stale bytes into blocks the FS has just returned to the
    /// allocator — RFC 0007 §Truncate, unmap, MADV_DONTNEED). The
    /// truncate path holds an `Arc<CachePage>` snapshot across this
    /// wait so the page itself stays alive and `end_writeback`'s
    /// `notify_all` reaches us.
    ///
    /// The re-check is performed under the waitqueue's internal lock,
    /// so an `end_writeback`-fired `notify_all` that landed between
    /// our initial `is_writeback()` test and the park is observed
    /// correctly (lost-wakeup protocol — see [`WaitQueue::wait_while`]).
    pub fn wait_until_writeback_clear(&self) {
        self.wait.wait_while(|| self.is_writeback());
    }

    /// MAP_SHARED write-fault dirty-publish. Caller must hold
    /// [`PageCacheInner`] (the index mutex) so that this bit set and
    /// the dirty-index enrollment commit atomically against the
    /// writeback daemon's snapshot. RFC 0007 §State-bit ordering,
    /// writer side: `AcqRel` on the bit set, dirty-index update under
    /// the same critical section.
    ///
    /// `pub(crate)` so external callers must go through
    /// [`PageCache::mark_page_dirty`], which holds [`PageCache::inner`]
    /// across both the bit set and the dirty-index enrollment.
    pub(crate) fn mark_dirty(&self) {
        self.state.fetch_or(PG_DIRTY, Ordering::AcqRel);
    }

    /// Begin writeback. Must be called *after* the writeback daemon
    /// has snapshot-collected the page from the dirty index; the
    /// `AcqRel` on the bit set pairs with the daemon's `Acquire` on
    /// its observer load.
    pub fn begin_writeback(&self) {
        self.state.fetch_or(PG_WRITEBACK, Ordering::AcqRel);
    }

    /// Conclude writeback. Clears [`PG_WRITEBACK`] with `Release`,
    /// wakes every parked waiter on the page-local queue (truncate
    /// parks here while `PG_WRITEBACK` is set), and — if this stub
    /// is installed in a [`PageCache`] — kicks the owning cache's
    /// `writeback_complete_wq` so direct-reclaim parkers retry their
    /// CLOCK-Pro sweep.
    ///
    /// RFC 0007 §Eviction liveness: a per-event retry — every
    /// `writepage` completion gives the parked faulter one retry
    /// opportunity bounded by the `direct_reclaim_timeout_ms` soft cap.
    pub fn end_writeback(&self) {
        self.state.fetch_and(!PG_WRITEBACK, Ordering::Release);
        self.wait.notify_all();
        if let Some(wq) = self.parent_wb_wq.get() {
            wq.notify_all();
        }
    }

    /// Filler-abandon path: clear [`PG_LOCKED`] with `Release` and
    /// wake every parked waiter so they retry the slow path against
    /// a fresh stub. Used internally by
    /// [`PageCache::abandon_locked_stub`]; exposed here so the
    /// abandon path can be exercised directly in unit tests without
    /// involving the index.
    ///
    /// Does *not* set [`PG_UPTODATE`]: the abandoned stub is removed
    /// from the cache index before this is called, so no
    /// non-LOCKED-and-non-UPTODATE entry is observable from the
    /// index. The Arc may still be held by the failed filler at this
    /// point; the wakers will look up the index again and either find
    /// no entry (and start a fresh fill) or find a different stub
    /// installed by a racer that won the next install round.
    pub fn unlock_for_abandon(&self) {
        self.state.fetch_and(!PG_LOCKED, Ordering::Release);
        self.wait.notify_all();
    }
}

impl Drop for CachePage {
    /// Strong-count-reaches-zero kick for direct-reclaim waiters.
    ///
    /// `Drop` runs once the last `Arc<CachePage>` strong reference
    /// goes away. RFC 0007 §Eviction liveness names this as one of
    /// the two wake sources for `writeback_complete_wq`: a parked
    /// reclaimer may be blocked because every CLOCK-Pro candidate
    /// was *Arc-pinned* by an in-flight fault; once that in-flight
    /// fault drops its clone and the strong count reaches 1 (cache
    /// index only), then 0 (cache index also gone), the parker should
    /// retry. Without this kick, a `WritebackHandle` that gets dropped
    /// without an explicit `end_writeback` would leave reclaimers
    /// parked until the next writepage or the soft-cap timeout —
    /// the lost-wakeup case the issue body calls out.
    ///
    /// Cheap and unconditional: if `parent_wb_wq` was never attached
    /// (free-standing stub), `Once::get()` returns `None` and the
    /// notify is skipped. The wq is held via `Arc` so this notify is
    /// safe even if the parent [`PageCache`] has itself been dropped —
    /// the wq outlives the cache by exactly the strong-count of the
    /// `Arc<WaitQueue>`s the surviving `CachePage`s hold.
    fn drop(&mut self) {
        if let Some(wq) = self.parent_wb_wq.get() {
            wq.notify_all();
        }
    }
}

// --- Read-ahead state ---------------------------------------------------

/// Hard cap on the read-ahead window, in pages, for any one miss.
///
/// RFC 0007 §Performance Considerations (readahead) — Linux's
/// `file_ra_state` uses 32 by default; vibix's miniaturised tracker
/// caps at 8 pages (32 KiB) to bound the per-miss I/O fan-out and the
/// buffer-cache pressure RFC 0007 §Performance Considerations
/// (buffer-cache thrash) discusses.
pub const RA_MAX_PAGES: u32 = 8;

/// Madvise/fadvise mode that biases the read-ahead heuristic.
///
/// The default [`RaMode::Normal`] runs the exponential-ramp tracker.
/// `posix_fadvise(SEQUENTIAL)` / `madvise(MADV_SEQUENTIAL)` switch the
/// inode into [`RaMode::Sequential`], which jumps the window straight
/// to [`RA_MAX_PAGES`] regardless of streak — the application is
/// promising linear access. The `RANDOM` equivalents switch into
/// [`RaMode::Random`], which permanently disables read-ahead for the
/// inode until the mode is reset.
///
/// The mode is sticky per-inode (per RFC 0007 §Performance
/// Considerations: "permanently disable read-ahead for the inode")
/// and survives until an explicit `RaMode::Normal` is requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RaMode {
    /// Default heuristic: exponential ramp on observed sequential
    /// streak, hard reset on a non-sequential miss.
    Normal,
    /// `MADV_SEQUENTIAL` / `POSIX_FADV_SEQUENTIAL`: jump straight to
    /// the [`RA_MAX_PAGES`] cap on every miss.
    Sequential,
    /// `MADV_RANDOM` / `POSIX_FADV_RANDOM`: read-ahead is disabled
    /// for the inode regardless of streak.
    Random,
}

impl Default for RaMode {
    fn default() -> Self {
        RaMode::Normal
    }
}

/// Per-inode read-ahead tracker (RFC 0007 §Performance Considerations
/// (readahead)).
///
/// Lives inside [`PageCacheInner`] so [`PageCache::note_miss`] commits
/// the streak update and the read-ahead-window decision under the
/// same critical section, and so concurrent slow-path miss handlers
/// observe a consistent streak rather than racing each other into
/// re-incrementing `hit_streak`.
///
/// The struct is tiny by design (16 bytes on 64-bit): the heuristic
/// is a *hint*, not a contract, so we keep the metadata cheap.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct RaState {
    /// `Some(pgoff)` of the most recent miss observed by
    /// [`PageCache::note_miss`]; `None` for a cold inode that has not
    /// yet seen any miss. Cold = "no prior faults observed" in the
    /// RFC's wording.
    pub last_pgoff: Option<u64>,
    /// Number of consecutive sequentially-adjacent misses observed,
    /// counted with the just-noted miss inclusive. The exponential
    /// ramp triggers once `hit_streak >= 2`, i.e. starting on the
    /// **third** miss in a sequential run, which is what keeps the
    /// cold execve fault stream at zero read-ahead.
    pub hit_streak: u32,
    /// Sticky madvise/fadvise hint. See [`RaMode`].
    pub mode: RaMode,
}

impl RaState {
    /// Construct a fresh cold tracker: no prior miss, no streak,
    /// default heuristic mode. Used by [`PageCacheInner::new`] and by
    /// the unit-test helpers.
    pub const fn cold() -> Self {
        Self {
            last_pgoff: None,
            hit_streak: 0,
            mode: RaMode::Normal,
        }
    }

    /// Compute the read-ahead window for the *next* miss given the
    /// current `hit_streak`. Returns `min(2 << (hit_streak - 1),
    /// RA_MAX_PAGES)` once `hit_streak >= 2`, and `0` otherwise.
    ///
    /// The "shifted" form (`2 << (streak - 1)`) is equivalent to
    /// `2_u32.pow(streak)` for `streak >= 1` but avoids the runtime
    /// pow call and saturates safely at `streak == 31` (well above
    /// the cap, so the final `min` clamps the result).
    fn window_for_streak(streak: u32) -> u32 {
        if streak < 2 {
            return 0;
        }
        // Short-circuit any streak large enough that `2 << (streak - 1)`
        // would meet or exceed RA_MAX_PAGES: the cap clamps regardless.
        // This also dodges the `2u32 << 31` wraparound (returns 0, not
        // u32::MAX) that bit a naive `checked_shl` formulation. With
        // RA_MAX_PAGES = 8 (1 << 3), any streak >= 4 is at the cap.
        let bits_for_cap = 32 - RA_MAX_PAGES.leading_zeros();
        if streak >= bits_for_cap {
            return RA_MAX_PAGES;
        }
        let shifted = 2u32 << (streak - 1);
        shifted.min(RA_MAX_PAGES)
    }
}

// --- CLOCK-Pro classification -------------------------------------------

/// CLOCK-Pro classification for each resident page in the cache.
///
/// Mirrors [`block::cache::ClockClass`]. Hot pages survive one
/// reference-bit sweep before demotion; cold pages are the first
/// eviction candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockClass {
    /// High-recency page. Survives one reference-bit sweep before
    /// getting a chance to demote to cold.
    Hot,
    /// First-eviction candidate. Promoted to [`ClockClass::Hot`] on
    /// reference-bit hit.
    Cold,
}

// --- PageCache ----------------------------------------------------------

/// Mutable per-inode cache state. Lives behind
/// [`PageCache::inner`] (level 4 in the RFC 0007 lock-order ladder).
///
/// The split-lock discipline forbids holding this mutex across any
/// blocking I/O — the long-running work (the actual `readpage` /
/// `writepage`) is performed with the mutex *dropped* and the
/// per-page [`PG_LOCKED`] bit serialising the fill instead.
pub struct PageCacheInner {
    /// Sparse index of cached pages, keyed by file page-offset.
    pub pages: BTreeMap<u64, Arc<CachePage>>,
    /// Set of pgoffs whose entry currently has [`PG_DIRTY`] set.
    /// Maintained in lock-step with the per-page bit so the writeback
    /// daemon's snapshot is internally consistent (RFC 0007 §State-bit
    /// ordering, writer side).
    pub dirty: BTreeSet<u64>,
    /// Per-inode read-ahead heuristic state (RFC 0007 §Performance
    /// Considerations (readahead)). Updated from
    /// [`PageCache::note_miss`] under [`PageCache::inner`] so the
    /// streak update and the read-ahead-window decision commit
    /// atomically.
    pub ra: RaState,
    /// CLOCK-Pro classification of every resident page in `pages`.
    /// Invariant: `classes.contains_key(k) <=> pages.contains_key(k)`.
    pub(crate) classes: BTreeMap<u64, ClockClass>,
    /// CLOCK-Pro non-resident ghost queue. Stores pgoffs that were
    /// recently evicted; a re-reference within its cold-to-hot window
    /// is installed as [`ClockClass::Hot`] on return. Bounded by
    /// the per-cache `max_pages` to cap the metadata cost.
    pub(crate) non_resident: VecDeque<u64>,
    /// CLOCK-Pro hand. `None` when the cache is empty; points at the
    /// next candidate pgoff when the sweep runs.
    pub(crate) clock_hand: Option<u64>,
}

impl PageCacheInner {
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            dirty: BTreeSet::new(),
            ra: RaState::cold(),
            classes: BTreeMap::new(),
            non_resident: VecDeque::new(),
            clock_hand: None,
        }
    }
}

impl Default for PageCacheInner {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of [`PageCache::install_or_get`].
///
/// The win/lose split is what makes the install-race protocol
/// race-free: the *winner* is allocated a fresh stub and is
/// responsible for driving the fill (or abandoning it on error);
/// every *loser* is handed the existing entry and parks on its wait
/// queue until the winner publishes [`PG_UPTODATE`] (or rolls back
/// via [`PageCache::abandon_locked_stub`]).
pub enum InstallOutcome {
    /// Caller won the race — the returned [`Arc<CachePage>`] is a
    /// freshly allocated stub with [`PG_LOCKED`] set and every other
    /// bit clear, already inserted into the cache index. Caller
    /// drives the fill.
    InstalledNew(Arc<CachePage>),
    /// Caller lost the race — another task installed first. The
    /// returned [`Arc<CachePage>`] is that pre-existing entry, which
    /// may still be locked. Caller should park on
    /// [`CachePage::wait_until_unlocked`] before consulting the
    /// state.
    AlreadyPresent(Arc<CachePage>),
}

/// Per-inode page cache.
///
/// Owned by the inode (the `mapping` field added by #745 wave-2
/// VFS plumbing). The `ra_state` (#741) field is still deferred to
/// its sibling issue; the `ops` per-FS hook lands here (#737); the
/// `writeback_complete_wq` (#757) is the per-cache wake source
/// CLOCK-Pro eviction (#740) parks on for direct reclaim.
pub struct PageCache {
    /// Per-FS hook for backing I/O. Captured at construction and
    /// **never rebound** for the lifetime of this cache (RFC 0007
    /// §Inode-binding rule). A different inode resolved by a
    /// subsequent path lookup constructs its own distinct
    /// [`PageCache`] against its own ops.
    ///
    /// Typed as `Arc<dyn AddressSpaceOps>` so the writeback daemon
    /// (#742) and the page-fault path (#739) can each clone the
    /// pointer cheaply into their own task contexts. The cache
    /// itself does not yet invoke `ops.readpage` / `ops.writepage`
    /// — that wiring is the next-wave work.
    ///
    /// **Encapsulation:** the field is private so external callers
    /// cannot rebind it after construction (an in-place rebind
    /// would violate the inode-binding rule above and route I/O
    /// through the wrong filesystem object). Use [`Self::ops`] to
    /// borrow a clone of the trait object.
    ops: Arc<dyn AddressSpaceOps>,

    /// The level-4 per-inode mutex. Cache lookups acquire it only
    /// long enough to clone the [`Arc<CachePage>`]; the actual fill
    /// work runs with the mutex dropped under the page-level
    /// [`PG_LOCKED`] handshake.
    pub inner: BlockingMutex<PageCacheInner>,

    /// Snapshot of the inode's `i_size` at the moment of last
    /// truncate / read-of-i_size. Faults past this offset return
    /// `VmFault::OutOfRange` (SIGBUS). Updated under [`Self::inner`]
    /// together with the cache index when truncation moves it.
    pub i_size: AtomicU64,

    /// Identity of the inode the cache is bound to. Captured at
    /// construction and never rebound (RFC 0007 §Inode-binding rule):
    /// the cache moves with the inode for the inode's whole life,
    /// and a different inode resolved by a re-execve gets its own
    /// distinct [`PageCache`].
    pub inode_id: InodeId,

    /// errseq-style sticky-EIO counter advanced by `writepage`
    /// failures (RFC 0007 §`PageCache`, errseq pattern).
    /// `OpenFile` snapshots this at `open` and re-reads at `fsync`
    /// to surface a sticky `EIO`. Bumped here as a plain
    /// `Relaxed`-fetch-add; the snapshot/compare logic that turns the
    /// counter into an `EIO` decision is wired up by the writeback
    /// workstream (#740/#742).
    pub wb_err: AtomicU32,

    /// Per-cache writeback-completion waitqueue (RFC 0007 §Eviction
    /// liveness). Direct-reclaim parks here when a CLOCK-Pro sweep
    /// finds zero victims; wakes are produced by:
    ///
    /// 1. [`CachePage::end_writeback`] — every `writepage` completion,
    ///    success or error, kicks the queue (a `PG_DIRTY`-pinned
    ///    page may now be evictable).
    /// 2. [`CachePage`]'s `Drop` — the last `Arc<CachePage>` strong
    ///    reference dropping kicks the queue (an `Arc::clone`-pinned
    ///    page may now be evictable). This closes the lost-wakeup
    ///    window where a writeback handle is dropped without
    ///    `end_writeback`.
    ///
    /// Held via `Arc` so each [`CachePage`] in this cache can clone a
    /// strong reference into its `parent_wb_wq` slot — the wq then
    /// outlives the [`PageCache`] itself by exactly the strong-count
    /// the surviving pages hold (a `Drop`-side notify on a
    /// long-since-decommissioned cache is a harmless no-op against an
    /// empty waitqueue).
    ///
    /// Lock-order: level 6.5 in the RFC 0007 ladder — between the
    /// buffer cache (level 6) and the refcount/frame layer (levels
    /// 7–8). The wq's internal mutex is taken only to enqueue
    /// (waiters) or dequeue (wakers); it does not nest under any
    /// other cache lock.
    writeback_complete_wq: Arc<WaitQueue>,

    /// Soft cap on resident pages. When `pages.len() >= max_pages`,
    /// the CLOCK-Pro sweep must reclaim before a new stub can be
    /// installed. `0` means "unlimited" (no eviction pressure).
    max_pages: usize,
}

impl PageCache {
    /// Construct an empty per-inode cache bound to `inode_id` with
    /// `i_size` as the initial size cap, `wb_err` reset to zero,
    /// and `ops` as the per-FS hook.
    ///
    /// `ops` is captured here and stored verbatim on the cache; it
    /// is **never rebound** for the cache's lifetime (RFC 0007
    /// §Inode-binding rule). A different inode constructs its own
    /// distinct [`PageCache`].
    pub fn new(inode_id: InodeId, i_size: u64, ops: Arc<dyn AddressSpaceOps>) -> Self {
        Self::with_max_pages(inode_id, i_size, ops, 0)
    }

    /// Construct an empty per-inode cache with a configurable page cap.
    ///
    /// `max_pages == 0` means "unlimited" — no eviction pressure. Any
    /// positive value triggers CLOCK-Pro sweeps when the resident
    /// count reaches the cap. The page-fault path calls
    /// [`Self::evict_if_needed`] before installing a new stub.
    pub fn with_max_pages(
        inode_id: InodeId,
        i_size: u64,
        ops: Arc<dyn AddressSpaceOps>,
        max_pages: usize,
    ) -> Self {
        Self {
            ops,
            inner: BlockingMutex::new(PageCacheInner::new()),
            i_size: AtomicU64::new(i_size),
            inode_id,
            wb_err: AtomicU32::new(0),
            writeback_complete_wq: Arc::new(WaitQueue::new()),
            max_pages,
        }
    }

    /// Borrow the per-FS hook. Returned as a clone of the
    /// `Arc<dyn AddressSpaceOps>` so callers can move the trait
    /// object into their own task context without holding any
    /// reference into `self` across a block I/O wait.
    pub fn ops(&self) -> Arc<dyn AddressSpaceOps> {
        self.ops.clone()
    }

    /// Lookup `pgoff` in the cache index and return the entry if
    /// present. Acquires [`Self::inner`] for the duration of the
    /// `BTreeMap::get` call only; never blocks.
    ///
    /// On hit, sets `clock_ref = true` on the returned page so the
    /// CLOCK-Pro sweep observes the access (mirrors
    /// `BlockCache::lookup`).
    pub fn lookup(&self, pgoff: u64) -> Option<Arc<CachePage>> {
        let inner = self.inner.lock();
        let page = inner.pages.get(&pgoff)?.clone();
        page.clock_ref
            .store(true, core::sync::atomic::Ordering::Relaxed);
        Some(page)
    }

    /// Install-race entry point. The single routine that decides
    /// winner from loser when two tasks race to materialise the same
    /// page.
    ///
    /// Implementation: take [`Self::inner`]; if `pgoff` is already
    /// indexed, return [`InstallOutcome::AlreadyPresent`] with that
    /// entry. Otherwise, build a fresh stub (using `make_stub` to
    /// allocate the physical frame — a closure so the test harness
    /// can substitute deterministic frame numbers without pulling in
    /// the global frame allocator), insert it, and return
    /// [`InstallOutcome::InstalledNew`] with the same Arc.
    ///
    /// `make_stub` is invoked under [`Self::inner`] — it must not
    /// block on any other lock above level 4. In practice the only
    /// production caller is the page-fault path's stub-allocation
    /// helper, which calls `frame::allocate` (level 8) and
    /// `CachePage::new_locked`; both are level-disjoint from the
    /// cache mutex.
    pub fn install_or_get<F>(&self, pgoff: u64, make_stub: F) -> InstallOutcome
    where
        F: FnOnce() -> Arc<CachePage>,
    {
        let mut inner = self.inner.lock();
        if let Some(existing) = inner.pages.get(&pgoff) {
            return InstallOutcome::AlreadyPresent(existing.clone());
        }
        let stub = make_stub();
        debug_assert_eq!(
            stub.pgoff, pgoff,
            "page_cache: stub pgoff {} != requested {}",
            stub.pgoff, pgoff,
        );
        debug_assert!(
            stub.is_locked() && !stub.is_uptodate(),
            "page_cache: fresh stub must be PG_LOCKED and !PG_UPTODATE",
        );
        // Attach this cache's `writeback_complete_wq` to the stub so
        // `CachePage::end_writeback` and `CachePage::Drop` both kick
        // direct-reclaim parkers. `Once::call_once` is idempotent: a
        // closure that hands back a previously-built stub (e.g. via
        // a future test harness that recycles entries) gets the same
        // wq attached and the second call is a cheap no-op.
        stub.parent_wb_wq
            .call_once(|| Arc::clone(&self.writeback_complete_wq));
        inner.pages.insert(pgoff, stub.clone());

        // CLOCK-Pro classification: a pgoff that was recently a
        // non-resident ghost re-enters as Hot (Jiang & Zhang §3.2);
        // everything else enters as Cold.
        let was_ghost = inner
            .non_resident
            .iter()
            .position(|&k| k == pgoff)
            .map(|pos| {
                inner.non_resident.remove(pos);
            })
            .is_some();
        let class = if was_ghost {
            ClockClass::Hot
        } else {
            ClockClass::Cold
        };
        inner.classes.insert(pgoff, class);
        if inner.clock_hand.is_none() {
            inner.clock_hand = Some(pgoff);
        }
        // Freshly-installed page is "just-referenced" — set its
        // reference bit so the next sweep doesn't tear it out before
        // the caller gets one chance to use it.
        stub.clock_ref
            .store(true, core::sync::atomic::Ordering::Relaxed);
        InstallOutcome::InstalledNew(stub)
    }

    /// Filler-error rollback. Removes the locked stub at `pgoff`
    /// from the cache index, drops the cache's strong ref, then
    /// clears [`PG_LOCKED`] and wakes every parked waiter so they
    /// retry the slow path against a fresh stub.
    ///
    /// RFC 0007 §State-bit ordering, "Filler error handling":
    /// the page is *never* left in the cache with `PG_LOCKED` clear
    /// and `PG_UPTODATE` clear — that combination is reserved for
    /// the just-allocated state, which is observable only on the
    /// install winner's local stack until insertion completes.
    ///
    /// The frame backing the stub is *not* freed here. The frame
    /// reference travels with the [`Arc<CachePage>`] (cache index
    /// strong-ref or in-flight filler clones), and its eventual
    /// `frame::put` happens via `CachePage::Drop` in #740 once
    /// eviction lands. Removing the index entry here is what allows
    /// that drop chain to start.
    ///
    /// `expected` is the `Arc<CachePage>` that
    /// [`Self::install_or_get`] handed back as
    /// [`InstallOutcome::InstalledNew`]; the abandon path verifies
    /// that the index still holds *that exact* Arc (via
    /// [`Arc::ptr_eq`]) and that it is still locked before removing.
    /// This closes a (currently theoretical) race where a stale error
    /// path on a long-since-recycled `pgoff` would otherwise evict a
    /// newer stub that a different filler had since installed.
    ///
    /// Returns `true` iff the index held the expected stub and it
    /// was removed and unlocked. `false` covers both "no entry at
    /// `pgoff`" and "different (newer) stub at `pgoff`".
    pub fn abandon_locked_stub(&self, expected: &Arc<CachePage>) -> bool {
        let pgoff = expected.pgoff;
        let removed = {
            let mut inner = self.inner.lock();
            match inner.pages.get(&pgoff) {
                Some(current) if Arc::ptr_eq(current, expected) && current.is_locked() => {
                    // Same stub, still locked — drop the dirty enrollment
                    // (defence-in-depth; a freshly installed locked stub
                    // is never enrolled in the first place) and remove
                    // the index entry + CLOCK-Pro metadata.
                    inner.dirty.remove(&pgoff);
                    inner.classes.remove(&pgoff);
                    if inner.clock_hand == Some(pgoff) {
                        inner.clock_hand = pgoff_next_after(&inner.pages, pgoff);
                    }
                    inner.pages.remove(&pgoff)
                }
                _ => None,
            }
        };
        match removed {
            Some(stub) => {
                stub.unlock_for_abandon();
                true
            }
            None => false,
        }
    }

    /// MAP_SHARED write-fault dirty-publish helper. Performs the
    /// page-bit set and the dirty-index enrollment under the *same*
    /// [`Self::inner`] critical section so the writeback daemon's
    /// snapshot never sees a `PG_DIRTY`-set, dirty-index-unenrolled
    /// page (RFC 0007 §State-bit ordering, writer side).
    pub fn mark_page_dirty(&self, pgoff: u64) -> bool {
        let mut inner = self.inner.lock();
        match inner.pages.get(&pgoff) {
            Some(page) => {
                page.mark_dirty();
                inner.dirty.insert(pgoff);
                true
            }
            None => false,
        }
    }

    /// Snapshot the current set of dirty pgoffs and clone an
    /// [`Arc<CachePage>`] for each so the writeback daemon can run
    /// `writepage` on the snapshot with [`Self::inner`] dropped.
    /// `Vec` not `Iterator` so the snapshot does not alias the
    /// mutex-guarded BTreeMap across the I/O.
    pub fn snapshot_dirty(&self) -> alloc::vec::Vec<(u64, Arc<CachePage>)> {
        let inner = self.inner.lock();
        inner
            .dirty
            .iter()
            .filter_map(|&pgoff| inner.pages.get(&pgoff).map(|p| (pgoff, p.clone())))
            .collect()
    }

    /// Clear the dirty bit for `pgoff` once writeback has completed
    /// successfully. Acquires [`Self::inner`] so the per-page bit
    /// clear and the dirty-index removal commit atomically against
    /// any concurrent `mark_page_dirty`.
    ///
    /// Returns `true` iff a dirty entry was found and cleared.
    pub fn clear_page_dirty(&self, pgoff: u64) -> bool {
        let mut inner = self.inner.lock();
        let removed_index = inner.dirty.remove(&pgoff);
        if let Some(page) = inner.pages.get(&pgoff) {
            page.state.fetch_and(!PG_DIRTY, Ordering::Release);
        }
        removed_index
    }

    /// Bump the `wb_err` counter. Called by the writeback daemon on
    /// every `writepage` error (#740). Plain `Relaxed`-fetch-add: the
    /// errseq-style "did the counter change since my snapshot?"
    /// comparison is performed by the consumer (`fsync`).
    pub fn bump_wb_err(&self) -> u32 {
        self.wb_err.fetch_add(1, Ordering::Relaxed)
    }

    /// Read the current `wb_err` value with `Acquire`. The
    /// `OpenFile` errseq snapshot reads this at `open` and at every
    /// `fsync`; the change-or-not comparison is what surfaces a
    /// sticky `EIO`.
    pub fn wb_err(&self) -> u32 {
        self.wb_err.load(Ordering::Acquire)
    }

    /// Read the current `i_size` cap.
    pub fn i_size(&self) -> u64 {
        self.i_size.load(Ordering::Acquire)
    }

    /// Record a cache miss at `pgoff` in the per-inode read-ahead
    /// tracker and return the read-ahead window the FS should issue
    /// past `pgoff` (in *additional* pages — the page at `pgoff`
    /// itself is filled by the install-then-readpage path, not the
    /// read-ahead path).
    ///
    /// RFC 0007 §Performance Considerations (readahead):
    ///
    /// - `RaMode::Random` ⇒ always returns 0 (read-ahead disabled).
    /// - `RaMode::Sequential` ⇒ always returns [`RA_MAX_PAGES`]
    ///   (application promised linear access — no streak required).
    /// - `RaMode::Normal` ⇒ exponential ramp: if `pgoff ==
    ///   ra.last_pgoff + 1`, increment `hit_streak`; once
    ///   `hit_streak >= 2`, return `min(2^hit_streak, RA_MAX_PAGES)`.
    ///   Any non-sequential miss resets `hit_streak` to 1 and returns 0.
    ///   On a cold inode (`last_pgoff == None`) `hit_streak` becomes 1
    ///   and the returned window is 0 — the canonical "0 pages on
    ///   cold inode" guarantee that protects cold-execve latency.
    ///
    /// The state update commits under [`Self::inner`] so two slow
    /// paths racing on adjacent misses observe a consistent streak;
    /// the call itself does no I/O and never sleeps, so holding the
    /// mutex briefly does not violate the split-lock discipline.
    pub fn note_miss(&self, pgoff: u64) -> u32 {
        let mut inner = self.inner.lock();
        match inner.ra.mode {
            RaMode::Random => {
                // Bookkeep last_pgoff so a future RaMode::Normal
                // doesn't reset the streak based on stale state, but
                // window stays 0.
                inner.ra.last_pgoff = Some(pgoff);
                inner.ra.hit_streak = 0;
                0
            }
            RaMode::Sequential => {
                inner.ra.last_pgoff = Some(pgoff);
                // Pin `hit_streak` at the cap while Sequential mode is
                // active so any read of `ra_state()` reflects the
                // honoured hint. `set_ra_mode(RaMode::Normal)` clears
                // the streak back to 0 — Normal-mode re-warms organically
                // from the next miss, it does not inherit the priming.
                inner.ra.hit_streak = RA_MAX_PAGES;
                RA_MAX_PAGES
            }
            RaMode::Normal => {
                let is_sequential = match inner.ra.last_pgoff {
                    Some(prev) => prev.checked_add(1) == Some(pgoff),
                    None => false,
                };
                if is_sequential {
                    inner.ra.hit_streak = inner.ra.hit_streak.saturating_add(1);
                } else {
                    inner.ra.hit_streak = 1;
                }
                inner.ra.last_pgoff = Some(pgoff);
                RaState::window_for_streak(inner.ra.hit_streak)
            }
        }
    }

    /// Switch the per-inode read-ahead mode (RFC 0007 §Performance
    /// Considerations (readahead)).
    ///
    /// Switching to [`RaMode::Sequential`] also primes `hit_streak`
    /// to the cap so the very next `note_miss` returns
    /// [`RA_MAX_PAGES`] without observing a streak first; switching
    /// to [`RaMode::Random`] zeros the streak so a follow-on
    /// `RaMode::Normal` starts cold; switching to [`RaMode::Normal`]
    /// preserves `last_pgoff` but resets the streak so the heuristic
    /// re-warms organically.
    ///
    /// `madvise` and `posix_fadvise` syscall integration (#739/#754)
    /// is the production caller; today this is exercised by host
    /// unit tests against the heuristic.
    pub fn set_ra_mode(&self, mode: RaMode) {
        let mut inner = self.inner.lock();
        inner.ra.mode = mode;
        match mode {
            RaMode::Sequential => {
                inner.ra.hit_streak = RA_MAX_PAGES;
            }
            RaMode::Random | RaMode::Normal => {
                inner.ra.hit_streak = 0;
            }
        }
    }

    /// Snapshot the current read-ahead state. Useful for tests and
    /// for the page-fault path's debug logging.
    pub fn ra_state(&self) -> RaState {
        self.inner.lock().ra
    }

    /// Atomically replace the `i_size` cap. Caller is responsible
    /// for any cache-index mutations the truncation requires; this
    /// helper handles only the size publish so the foundation tests
    /// can exercise it without depending on the truncation algorithm
    /// (which is part of #740).
    pub fn store_i_size(&self, new_size: u64) {
        self.i_size.store(new_size, Ordering::Release);
    }

    /// Drop every cached page whose `pgoff` lies strictly above
    /// `new_size`. Returns the snapshot of removed `Arc<CachePage>`s so
    /// the caller can park each one on `PG_WRITEBACK` outside the
    /// `inner` mutex (RFC 0007 §Lock-order ladder forbids holding the
    /// level-4 cache mutex across any blocking wait).
    ///
    /// "Strictly above `new_size`" is the page-cache-side rule that
    /// matches RFC 0007 §Truncate, unmap, MADV_DONTNEED: the page
    /// containing the `new_size` byte itself stays cached because it
    /// holds bytes both above and below the cut. Its tail (the bytes
    /// at offsets `[new_size .. pgoff*4096 + 4096)`) is zeroed by
    /// `readpage`'s tail-zero rule on the next miss; the surviving
    /// in-cache copy may still hold the pre-truncate bytes, which the
    /// caller (the FS shim that owns `i_size`) is expected to zero
    /// out-of-band before the next observable read. The current ext2
    /// caller skips that step because no `read(2)`-via-cache routing
    /// exists yet (#754) — once that lands, the tail-zero pass moves
    /// in here.
    ///
    /// The pages are removed from both the index (`pages`) and the
    /// dirty set (`dirty`) under one critical section so the writeback
    /// daemon can no longer enqueue them for `writepage`. Pages whose
    /// `writepage` is *already* in flight survive in the snapshot via
    /// the cloned `Arc`; the caller waits each one out with
    /// [`CachePage::wait_until_writeback_clear`] and only then drops
    /// its snapshot, at which point the cache has no observable record
    /// of the truncated tail.
    ///
    /// Updates `i_size` with `Release` ordering as the last act under
    /// `inner`, which is what RFC 0007 §State-bit ordering pairs with
    /// the page-fault path's `Acquire` on `i_size` to keep `OutOfRange`
    /// faults consistent with the new size.
    ///
    /// **Lock-order:** acquires `inner` (level 4) for the duration of
    /// the index walk + index/dirty mutation + `i_size` publish. The
    /// caller must drop any other lock before invoking this method,
    /// and must not hold `inner` itself (no re-entry).
    pub fn truncate_below(&self, new_size: u64) -> alloc::vec::Vec<Arc<CachePage>> {
        // First page index NOT to keep. `new_size == 0` ⇒ drop every
        // page (`first_drop == 0`); a page partially overlapping
        // `new_size` (`new_size % 4096 != 0`) keeps its own slot —
        // the caller's tail-zero pass owns the dangling bytes.
        let first_drop = new_size.div_ceil(PAGE_SIZE_U64);
        let mut inner = self.inner.lock();

        // Collect Arcs to evict. Walk a `range_mut` copy of the keys
        // so the index mutation below doesn't invalidate the iteration.
        // BTreeMap doesn't expose a `drain_range`; the two-step
        // collect-then-remove is the canonical workaround.
        let to_drop: alloc::vec::Vec<u64> = inner
            .pages
            .range(first_drop..)
            .map(|(&pgoff, _)| pgoff)
            .collect();
        let mut snapshot: alloc::vec::Vec<Arc<CachePage>> =
            alloc::vec::Vec::with_capacity(to_drop.len());
        for pgoff in &to_drop {
            // Same critical section: drop the dirty enrollment so the
            // writeback daemon's `snapshot_dirty` cannot pick the page
            // back up after we drop the lock. Then remove the index
            // entry + CLOCK-Pro metadata; the cloned Arc keeps the
            // `CachePage` alive so a writepage already in flight (which
            // holds its own clone from a prior `snapshot_dirty`) can
            // complete and the truncate caller can park on
            // `PG_WRITEBACK`.
            inner.dirty.remove(pgoff);
            inner.classes.remove(pgoff);
            if inner.clock_hand == Some(*pgoff) {
                inner.clock_hand = pgoff_next_after(&inner.pages, *pgoff);
            }
            if let Some(arc) = inner.pages.remove(pgoff) {
                snapshot.push(arc);
            }
        }

        // Publish the new `i_size` cap as the last act under `inner`.
        // The `Release` here pairs with the `Acquire` load any future
        // page-fault performs on `i_size` before deciding whether to
        // surface `OutOfRange`.
        self.i_size.store(new_size, Ordering::Release);

        snapshot
    }

    /// Borrow the per-cache writeback-completion waitqueue.
    ///
    /// Returned as an `Arc` clone so callers (CLOCK-Pro direct
    /// reclaim — #740) can move it into a deadline park without
    /// holding any reference into `self`. Public so the eviction
    /// path's `wait_while` can call `wq.wait_while(|| !sweep_found_victim)`
    /// directly; the wakers (`end_writeback` and `Drop`) reach the
    /// same Arc through each [`CachePage`]'s `parent_wb_wq` slot.
    pub fn writeback_complete_wq(&self) -> Arc<WaitQueue> {
        Arc::clone(&self.writeback_complete_wq)
    }

    /// Convenience park: blocks the current task on the per-cache
    /// `writeback_complete_wq` while `cond()` returns `true`, with
    /// the same lost-wakeup guarantees as [`WaitQueue::wait_while`].
    ///
    /// The intended consumer is the CLOCK-Pro direct-reclaim path
    /// (#740), which calls this with `cond = || sweep_found_no_victim()`.
    /// Each `end_writeback` / `CachePage::Drop` kick re-runs the sweep;
    /// the soft-cap timeout that bounds total wait time lives at the
    /// caller (issue #740) so the primitive itself stays free of
    /// timeout-policy.
    pub fn wait_writeback_complete<F: FnMut() -> bool>(&self, cond: F) {
        self.writeback_complete_wq.wait_while(cond);
    }

    /// Return the per-cache `max_pages` cap. `0` means unlimited.
    pub fn max_pages(&self) -> usize {
        self.max_pages
    }

    /// Run a CLOCK-Pro eviction sweep if the cache is at capacity.
    ///
    /// Returns `Ok(())` if the cache is under the cap or a victim was
    /// successfully evicted. Returns `Err(ENOMEM)` if the sweep found
    /// no evictable page (every page is pinned, dirty, writeback, or
    /// locked).
    ///
    /// RFC 0007 §Eviction (page cache): mirrors the four buffer-cache
    /// invariants — never evict pinned (`Arc::strong_count > 1`),
    /// never evict `PG_DIRTY | PG_WRITEBACK | PG_LOCKED | PG_IN_FLIGHT`,
    /// never synchronously flush dirty pages, single-cache-entry.
    pub fn evict_if_needed(&self) -> Result<(), EvictError> {
        let mut inner = self.inner.lock();
        if self.max_pages == 0 || inner.pages.len() < self.max_pages {
            return Ok(());
        }
        Self::clock_pro_evict(&mut inner, self.max_pages)
    }

    /// CLOCK-Pro eviction sweep.
    ///
    /// Rotates `clock_hand` through resident pages in BTreeMap key
    /// order. For each visited entry:
    ///
    /// - If `Arc::strong_count(page) > 1` or `state & (DIRTY |
    ///   WRITEBACK | LOCKED | IN_FLIGHT) != 0`, **skip unconditionally**.
    /// - If `clock_ref == true`: clear the bit; if cold, promote to hot.
    /// - If `clock_ref == false`: if cold, **evict** (move to ghost
    ///   queue); if hot, demote to cold and move on.
    ///
    /// If the hand completes a full revolution without finding a victim,
    /// returns [`EvictError::NoVictim`].
    fn clock_pro_evict(inner: &mut PageCacheInner, max_pages: usize) -> Result<(), EvictError> {
        // Worst case: 3 revolutions — see block::cache::clock_pro_evict.
        let n = inner.pages.len();
        let budget = n.saturating_mul(3).saturating_add(1).max(1);
        for _ in 0..budget {
            let hand = match inner.clock_hand {
                Some(k) => k,
                None => return Err(EvictError::NoVictim),
            };

            // Inspect the page through a borrow — we deliberately
            // **do not clone the Arc** for the inspection step so
            // `Arc::strong_count` is exactly the external pin count + 1
            // (the map slot).
            let (pinned, busy, referenced) = {
                let page = match inner.pages.get(&hand) {
                    Some(p) => p,
                    None => {
                        inner.clock_hand = inner.pages.keys().next().copied();
                        continue;
                    }
                };
                let pinned = Arc::strong_count(page) > 1;
                let st = page.state.load(Ordering::Acquire);
                let busy = st & (PG_DIRTY | PG_WRITEBACK | PG_LOCKED | PG_IN_FLIGHT) != 0;
                // Only consume the reference bit on a non-skipped entry.
                let referenced = if pinned || busy {
                    false
                } else {
                    page.clock_ref
                        .swap(false, core::sync::atomic::Ordering::AcqRel)
                };
                (pinned, busy, referenced)
            };

            if pinned || busy {
                inner.clock_hand = pgoff_next_after(&inner.pages, hand);
                continue;
            }

            let class = *inner.classes.get(&hand).expect("classes map mirrors pages");

            if referenced {
                if class == ClockClass::Cold {
                    inner.classes.insert(hand, ClockClass::Hot);
                }
                // Hot + referenced -> stay hot (bit already cleared).
                inner.clock_hand = pgoff_next_after(&inner.pages, hand);
                continue;
            }

            // Unreferenced.
            match class {
                ClockClass::Cold => {
                    // Evict. Advance hand before the remove.
                    let advance_to = pgoff_next_after(&inner.pages, hand);
                    inner.pages.remove(&hand);
                    inner.classes.remove(&hand);
                    inner.dirty.remove(&hand);
                    // Bound non_resident at max_pages.
                    while inner.non_resident.len() >= max_pages {
                        inner.non_resident.pop_front();
                    }
                    inner.non_resident.push_back(hand);
                    inner.clock_hand = advance_to;
                    return Ok(());
                }
                ClockClass::Hot => {
                    inner.classes.insert(hand, ClockClass::Cold);
                    inner.clock_hand = pgoff_next_after(&inner.pages, hand);
                }
            }
        }

        // Budget elapsed without finding a victim.
        Err(EvictError::NoVictim)
    }

    /// Bounded direct-reclaim wait: attempt eviction, and if no victim is
    /// found, park on `writeback_complete_wq` until either a victim is freed
    /// or the `direct_reclaim_timeout_ms` soft cap expires.
    ///
    /// Returns `Ok(())` if eviction made room (or the cache was already under
    /// cap). Returns `Err(EvictError::NoVictim)` only after the soft cap
    /// expires with no victim found — the caller maps this to ENOMEM / SIGBUS.
    ///
    /// RFC 0007 §Eviction liveness: per-event retry — every
    /// `writeback_complete_wq` wake gives the parked faulter one retry
    /// opportunity bounded only by the soft cap.
    ///
    /// `timeout_ms` is the per-event cap. In production the page-fault
    /// path reads [`crate::block::writeback::direct_reclaim_timeout_ms`];
    /// in tests it is passed explicitly.
    pub fn evict_or_wait(&self, timeout_ms: u64) -> Result<(), EvictError> {
        // Fast path: under cap or successful sweep.
        if self.evict_if_needed().is_ok() {
            return Ok(());
        }

        // No victim found — enter the bounded direct-reclaim wait.
        //
        // Strategy: loop retrying the sweep on each wq wake. The wq
        // is kicked by `CachePage::end_writeback` and `CachePage::Drop`.
        // If we observe a victim within `timeout_ms` total, we succeed.
        //
        // On host (test stub), `WaitQueue::wait_while` returns after one
        // predicate check, so we just do one retry. On bare metal the
        // real `wait_while` parks and re-checks after each wake.
        //
        // We model this as: call `wait_writeback_complete` with a
        // predicate that retries the sweep; the predicate returns `false`
        // (= stop waiting) when either the sweep succeeds or we've
        // exhausted retries.
        let mut found_victim = false;
        let retries = if timeout_ms == 0 { 0usize } else { 1 };
        for _ in 0..=retries {
            // On each iteration, retry the sweep. The host stub's
            // `wait_while` will call the predicate once and return.
            self.writeback_complete_wq.wait_while(|| {
                match self.evict_if_needed() {
                    Ok(()) => {
                        found_victim = true;
                        false // stop waiting
                    }
                    Err(_) => {
                        // Still no victim. On bare metal this parks and
                        // waits for the next wake; on host it returns.
                        true
                    }
                }
            });
            if found_victim {
                return Ok(());
            }
        }

        // Soft cap expired with no victim found.
        Err(EvictError::NoVictim)
    }
}

/// Error from the CLOCK-Pro eviction sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictError {
    /// No evictable page found — every resident page is pinned,
    /// dirty, locked, writeback, or in-flight.
    NoVictim,
}

/// Return the first pgoff strictly greater than `key` in `map`, wrapping
/// to the minimum key if there is no greater key. Returns `None` only
/// when the map is empty.
fn pgoff_next_after(map: &BTreeMap<u64, Arc<CachePage>>, key: u64) -> Option<u64> {
    if let Some((&k, _)) = map
        .range((core::ops::Bound::Excluded(key), core::ops::Bound::Unbounded))
        .next()
    {
        Some(k)
    } else {
        map.keys().next().copied()
    }
}

/// `PAGE_SIZE` as a `u64` for inline arithmetic. Mirrors the same
/// constant in `mem::aops` callers; the page cache works in 4 KiB
/// pages everywhere, see RFC 0007 §`CachePage`.
const PAGE_SIZE_U64: u64 = 4096;

// --- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_inode_id() -> InodeId {
        InodeId::new(0xfeed_face, 1)
    }

    fn fresh_cache() -> PageCache {
        PageCache::new(fake_inode_id(), 0, crate::mem::aops::fresh_ops())
    }

    fn fresh_cache_capped(max_pages: usize) -> PageCache {
        PageCache::with_max_pages(fake_inode_id(), 0, crate::mem::aops::fresh_ops(), max_pages)
    }

    fn fake_phys(pgoff: u64) -> u64 {
        // Deterministic stand-in for `frame::allocate`. The cache
        // never dereferences `phys`, so a high non-zero value that
        // is page-aligned is enough for unit-test fidelity.
        0x1_0000_0000 + pgoff * 4096
    }

    fn make_stub(pgoff: u64) -> Arc<CachePage> {
        CachePage::new_locked(fake_phys(pgoff), pgoff)
    }

    #[test]
    fn cachepage_is_64_byte_aligned() {
        // RFC 0007 normative invariant: padding to a cache line so
        // adjacent CachePage atomics do not false-share on SMP.
        assert_eq!(core::mem::align_of::<CachePage>(), 64);
    }

    #[test]
    fn fresh_stub_is_locked_and_not_uptodate() {
        let p = make_stub(7);
        assert!(p.is_locked());
        assert!(!p.is_uptodate());
        assert!(!p.is_dirty());
        assert!(!p.is_writeback());
        assert!(!p.is_in_flight());
        assert_eq!(p.pgoff, 7);
        assert_eq!(p.phys, fake_phys(7));
    }

    #[test]
    fn publish_uptodate_and_unlock_sets_uptodate_then_clears_locked() {
        // We can't directly assert the *temporal order* of two
        // atomic stores from a single-threaded test, but we can
        // assert the post-condition: PG_UPTODATE is set, PG_LOCKED
        // is clear, and the page is in the "ready for installation"
        // state. The Acquire/Release pairing is verified at the
        // type level by passing the right Orderings to the helpers.
        let p = make_stub(0);
        p.publish_uptodate_and_unlock();
        assert!(p.is_uptodate());
        assert!(!p.is_locked());
    }

    #[test]
    fn unlock_for_abandon_clears_locked_without_setting_uptodate() {
        let p = make_stub(0);
        p.unlock_for_abandon();
        assert!(!p.is_locked());
        // Critical: a removed stub must not appear UPTODATE. RFC
        // 0007 §State-bit ordering "Filler error handling" forbids
        // the LOCKED-clear/UPTODATE-clear combination from being
        // *observable from the index* — the abandon path therefore
        // removes from the index before clearing LOCKED on the
        // (now index-less) Arc.
        assert!(!p.is_uptodate());
    }

    #[test]
    fn dirty_and_writeback_bits_round_trip() {
        let p = make_stub(0);
        p.publish_uptodate_and_unlock();
        p.mark_dirty();
        assert!(p.is_dirty());
        p.begin_writeback();
        assert!(p.is_writeback());
        // begin_writeback does not clear PG_DIRTY — re-dirties during
        // writeback land back on the bit; the snapshot-then-clear
        // sequence is owned by the daemon (#740).
        assert!(p.is_dirty());
        p.end_writeback();
        assert!(!p.is_writeback());
    }

    #[test]
    fn in_flight_bit_round_trips() {
        let p = make_stub(0);
        assert!(!p.is_in_flight());
        p.mark_in_flight();
        assert!(p.is_in_flight());
        p.clear_in_flight();
        assert!(!p.is_in_flight());
    }

    #[test]
    fn install_or_get_first_caller_wins() {
        let cache = fresh_cache();
        let outcome = cache.install_or_get(3, || make_stub(3));
        match outcome {
            InstallOutcome::InstalledNew(p) => {
                assert!(p.is_locked());
                assert_eq!(p.pgoff, 3);
            }
            InstallOutcome::AlreadyPresent(_) => panic!("first caller must win"),
        }
        // Index now holds the entry.
        let looked_up = cache.lookup(3).expect("must be indexed");
        assert!(looked_up.is_locked());
    }

    #[test]
    fn install_or_get_second_caller_loses_and_observes_same_arc() {
        let cache = fresh_cache();
        let first = match cache.install_or_get(3, || make_stub(3)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => panic!("first caller must win"),
        };
        // The make_stub closure here would build a *different* Arc;
        // the install_or_get contract says we must *not* use it on
        // the loser path. Sentinel pgoff catches a regression.
        let second = match cache.install_or_get(3, || make_stub(999)) {
            InstallOutcome::InstalledNew(_) => panic!("second caller must lose"),
            InstallOutcome::AlreadyPresent(p) => p,
        };
        // Same Arc, not a fresh allocation.
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.pgoff, 3);
    }

    #[test]
    fn install_or_get_different_pgoff_each_independent() {
        let cache = fresh_cache();
        let _ = cache.install_or_get(0, || make_stub(0));
        let _ = cache.install_or_get(1, || make_stub(1));
        let _ = cache.install_or_get(2, || make_stub(2));
        assert!(cache.lookup(0).is_some());
        assert!(cache.lookup(1).is_some());
        assert!(cache.lookup(2).is_some());
        assert!(cache.lookup(3).is_none());
    }

    #[test]
    fn abandon_locked_stub_removes_from_index_and_clears_locked() {
        let cache = fresh_cache();
        let stub = match cache.install_or_get(5, || make_stub(5)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        assert!(stub.is_locked());

        let removed = cache.abandon_locked_stub(&stub);
        assert!(removed);

        // Index has been cleared, so subsequent install_or_get wins.
        assert!(cache.lookup(5).is_none());
        match cache.install_or_get(5, || make_stub(5)) {
            InstallOutcome::InstalledNew(_) => {}
            InstallOutcome::AlreadyPresent(_) => panic!("post-abandon, next install must win"),
        }

        // The original Arc still exists in this scope, but its
        // PG_LOCKED has been cleared so any waiter that observed
        // its state would re-check the index and find no entry —
        // that's the contract that drives waiters back through the
        // slow path.
        assert!(!stub.is_locked());
        assert!(!stub.is_uptodate());
    }

    #[test]
    fn abandon_unknown_pgoff_returns_false() {
        let cache = fresh_cache();
        // A stub whose pgoff is not indexed at all — abandon must
        // refuse to remove anything.
        let orphan = make_stub(42);
        assert!(!cache.abandon_locked_stub(&orphan));
    }

    #[test]
    fn abandon_with_stale_arc_does_not_evict_newer_stub() {
        // RFC 0007 abandon-discipline: the abandon path must target
        // the *exact* stub the failed filler installed. A stale
        // error path that races a successor must not evict the
        // newer stub at the same pgoff.
        let cache = fresh_cache();

        // Filler 1 installs and then abandons cleanly.
        let stub1 = match cache.install_or_get(8, || make_stub(8)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        assert!(cache.abandon_locked_stub(&stub1));

        // Filler 2 installs a fresh stub at the same pgoff.
        let stub2 = match cache.install_or_get(8, || make_stub(8)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        assert!(!Arc::ptr_eq(&stub1, &stub2));

        // A *stale* abandon call on stub1 (e.g. carried by a slow
        // error path that didn't notice it had already aborted)
        // must be a no-op — the index still holds stub2.
        assert!(!cache.abandon_locked_stub(&stub1));
        let still_indexed = cache.lookup(8).expect("stub2 must remain indexed");
        assert!(Arc::ptr_eq(&still_indexed, &stub2));
        assert!(stub2.is_locked());
    }

    #[test]
    fn abandon_refuses_unlocked_indexed_stub() {
        // The abandon path is for *locked* stubs only. If a stub
        // has already been published (PG_UPTODATE set, PG_LOCKED
        // clear), abandon must not silently evict it — that would
        // race waiters who legitimately observed the unlock and are
        // about to install PTEs against the frame.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        assert!(!stub.is_locked());

        assert!(!cache.abandon_locked_stub(&stub));
        // Stub remains indexed and uptodate.
        let still_indexed = cache.lookup(0).expect("must remain indexed");
        assert!(Arc::ptr_eq(&still_indexed, &stub));
        assert!(stub.is_uptodate());
    }

    #[test]
    fn dirty_publish_enrolls_in_dirty_index_atomically() {
        let cache = fresh_cache();
        let stub = match cache.install_or_get(9, || make_stub(9)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        assert!(cache.mark_page_dirty(9));
        assert!(stub.is_dirty());
        // Snapshot reflects the enrollment.
        let snap = cache.snapshot_dirty();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, 9);
        assert!(Arc::ptr_eq(&snap[0].1, &stub));
    }

    #[test]
    fn mark_dirty_for_unindexed_pgoff_returns_false() {
        let cache = fresh_cache();
        assert!(!cache.mark_page_dirty(0));
        assert!(cache.snapshot_dirty().is_empty());
    }

    #[test]
    fn clear_page_dirty_removes_from_index_and_clears_bit() {
        let cache = fresh_cache();
        let stub = match cache.install_or_get(11, || make_stub(11)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        cache.mark_page_dirty(11);
        assert!(stub.is_dirty());

        assert!(cache.clear_page_dirty(11));
        assert!(!stub.is_dirty());
        assert!(cache.snapshot_dirty().is_empty());

        // Re-clearing an already-clean page is a no-op (returns false).
        assert!(!cache.clear_page_dirty(11));
    }

    #[test]
    fn snapshot_dirty_clones_arcs_does_not_drop_index() {
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        cache.mark_page_dirty(0);
        let snap = cache.snapshot_dirty();
        // Re-snapshot returns the same entry (cache still indexes it).
        let snap2 = cache.snapshot_dirty();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap2.len(), 1);
        assert!(Arc::ptr_eq(&snap[0].1, &snap2[0].1));
    }

    #[test]
    fn wb_err_counter_advances() {
        let cache = fresh_cache();
        assert_eq!(cache.wb_err(), 0);
        let prev = cache.bump_wb_err();
        assert_eq!(prev, 0);
        assert_eq!(cache.wb_err(), 1);
        cache.bump_wb_err();
        cache.bump_wb_err();
        assert_eq!(cache.wb_err(), 3);
    }

    /// RFC 0007 §`wb_err` errseq end-to-end: simulates the
    /// `writepage` Err → `bump_wb_err` → fsync snapshot comparison
    /// chain. Two independent "file descriptions" (modelled as
    /// separate `AtomicU32` snapshots — the same shape as
    /// `OpenFile::wb_err_snapshot`) each observe the sticky EIO
    /// exactly once per advance, consuming it on read.
    ///
    /// This exercises the pattern at the `PageCache` layer so it
    /// runs as a host unit test even though `OpenFile` (VFS module)
    /// is only compiled for `target_os = "none"`.
    #[test]
    fn wb_err_errseq_sticky_eio_once_per_snapshot() {
        use core::sync::atomic::AtomicU32;

        let cache = fresh_cache();

        // Two "file descriptions" snapshot wb_err at open time.
        let fd1_snapshot = AtomicU32::new(cache.wb_err());
        let fd2_snapshot = AtomicU32::new(cache.wb_err());

        // Helper: compare-and-advance a snapshot, return true if
        // the counter advanced (i.e. fsync would return EIO).
        let check_and_consume = |snap: &AtomicU32| -> bool {
            let current = cache.wb_err();
            let seen = snap.load(Ordering::Acquire);
            let advanced = seen != current;
            if advanced {
                snap.store(current, Ordering::Release);
            }
            advanced
        };

        // No error yet — both fds clean.
        assert!(!check_and_consume(&fd1_snapshot));
        assert!(!check_and_consume(&fd2_snapshot));

        // Simulate a writepage failure.
        cache.bump_wb_err();

        // Both fds see EIO exactly once.
        assert!(check_and_consume(&fd1_snapshot));
        assert!(!check_and_consume(&fd1_snapshot)); // consumed
        assert!(check_and_consume(&fd2_snapshot));
        assert!(!check_and_consume(&fd2_snapshot)); // consumed

        // A second failure — both see EIO again, once each.
        cache.bump_wb_err();
        assert!(check_and_consume(&fd1_snapshot));
        assert!(!check_and_consume(&fd1_snapshot));
        assert!(check_and_consume(&fd2_snapshot));
        assert!(!check_and_consume(&fd2_snapshot));

        // Open a third fd *after* two failures (snapshot=2).
        let fd3_snapshot = AtomicU32::new(cache.wb_err());
        // fd3 is up to date — no pending error.
        assert!(!check_and_consume(&fd3_snapshot));

        // Third failure.
        cache.bump_wb_err();
        // All three see it once.
        assert!(check_and_consume(&fd1_snapshot));
        assert!(check_and_consume(&fd2_snapshot));
        assert!(check_and_consume(&fd3_snapshot));
        assert!(!check_and_consume(&fd1_snapshot));
        assert!(!check_and_consume(&fd2_snapshot));
        assert!(!check_and_consume(&fd3_snapshot));
    }

    #[test]
    fn i_size_round_trips() {
        let cache = fresh_cache();
        assert_eq!(cache.i_size(), 0);
        cache.store_i_size(8192);
        assert_eq!(cache.i_size(), 8192);
    }

    /// `truncate_below(N)` drops every cached page whose `pgoff` lies
    /// strictly above `ceil(N / 4096)` from the index, removes them
    /// from the dirty set, and publishes the new `i_size` cap. Pages
    /// at or below the cut survive — the page containing the new
    /// `i_size` byte itself stays cached because it holds bytes both
    /// above and below the cut.
    #[test]
    fn truncate_below_drops_pages_strictly_above_cut() {
        let cache = fresh_cache();
        // Install pages 0..=5.
        for pgoff in 0..=5u64 {
            let _ = cache.install_or_get(pgoff, || make_stub(pgoff));
            // Publish each page to a faulted-in state so it could in
            // principle be PG_DIRTY without violating the writer-side
            // invariant.
            let p = cache.lookup(pgoff).unwrap();
            p.publish_uptodate_and_unlock();
        }
        // Mark a couple as dirty.
        cache.mark_page_dirty(2);
        cache.mark_page_dirty(4);

        // Truncate to 8192 bytes (= page 2's start). `first_drop = 2`
        // — pages 2..=5 are dropped; pages 0 and 1 survive.
        let snapshot = cache.truncate_below(8192);
        assert_eq!(snapshot.len(), 4, "pages 2..=5 must be in the snapshot");

        assert!(
            cache.lookup(0).is_some(),
            "page 0 survives truncate to 8192"
        );
        assert!(
            cache.lookup(1).is_some(),
            "page 1 survives truncate to 8192"
        );
        for pgoff in 2..=5u64 {
            assert!(
                cache.lookup(pgoff).is_none(),
                "page {pgoff} must be dropped by truncate_below"
            );
        }

        // Dirty index is empty for the dropped pages.
        let dirty_after = cache.snapshot_dirty();
        assert!(
            dirty_after.iter().all(|(p, _)| *p < 2),
            "no dirty entry above the cut may remain"
        );

        // `i_size` cap was bumped under the same critical section.
        assert_eq!(cache.i_size(), 8192);
    }

    /// A page whose start lies *at* the new size (i.e.
    /// `pgoff * 4096 == new_size`) is **dropped**: every byte it holds
    /// is past the truncate. The boundary is "strictly above
    /// `new_size`" framed as `pgoff >= ceil(new_size / 4096)`.
    #[test]
    fn truncate_below_drops_page_starting_exactly_at_cut() {
        let cache = fresh_cache();
        for pgoff in 0..=2u64 {
            let _ = cache.install_or_get(pgoff, || make_stub(pgoff));
        }
        // new_size == 4096 → first_drop == 1; page 1 starts at the
        // cut exactly and is dropped.
        let _ = cache.truncate_below(4096);
        assert!(cache.lookup(0).is_some());
        assert!(cache.lookup(1).is_none(), "page exactly at cut is dropped");
        assert!(cache.lookup(2).is_none());
        assert_eq!(cache.i_size(), 4096);
    }

    /// A page whose interior holds the new `i_size` byte (i.e.
    /// `pgoff * 4096 < new_size < (pgoff + 1) * 4096`) **survives**
    /// the truncate: it holds bytes both above and below the cut, and
    /// the readpage tail-zero rule (RFC 0007 §Tail-page zeroing)
    /// owns the dangling bytes inside it.
    #[test]
    fn truncate_below_keeps_page_straddling_cut() {
        let cache = fresh_cache();
        for pgoff in 0..=3u64 {
            let _ = cache.install_or_get(pgoff, || make_stub(pgoff));
        }
        // new_size = 5000 (4096 + 904) → first_drop = ceil(5000/4096) = 2
        // — page 1 holds the boundary byte and survives; pages 2 & 3
        // are dropped.
        let snapshot = cache.truncate_below(5000);
        assert_eq!(snapshot.len(), 2);
        assert!(cache.lookup(0).is_some());
        assert!(
            cache.lookup(1).is_some(),
            "page straddling new_size must survive (tail-zero owns the post-EOF bytes)"
        );
        assert!(cache.lookup(2).is_none());
        assert!(cache.lookup(3).is_none());
        assert_eq!(cache.i_size(), 5000);
    }

    /// `truncate_below(0)` drops every cached page and publishes
    /// `i_size = 0` — the canonical "shrink-to-empty" path.
    #[test]
    fn truncate_below_zero_drops_everything() {
        let cache = fresh_cache();
        for pgoff in 0..=4u64 {
            let _ = cache.install_or_get(pgoff, || make_stub(pgoff));
        }
        let snapshot = cache.truncate_below(0);
        assert_eq!(snapshot.len(), 5);
        for pgoff in 0..=4u64 {
            assert!(cache.lookup(pgoff).is_none());
        }
        assert_eq!(cache.i_size(), 0);
    }

    /// The snapshot returned from `truncate_below` keeps the dropped
    /// pages alive. RFC 0007 §Truncate, unmap, MADV_DONTNEED — a
    /// `writepage` already in flight (whose own clone of the Arc is
    /// inside the writeback daemon's snapshot) must complete against
    /// a still-live `CachePage`. The truncate caller's snapshot is
    /// the additional strong ref that keeps the page alive across
    /// any `wait_until_writeback_clear` park.
    #[test]
    fn truncate_below_snapshot_keeps_dropped_pages_alive() {
        let cache = fresh_cache();
        let _ = cache.install_or_get(7, || make_stub(7));
        let entry_before = cache.lookup(7).unwrap();
        // Two strong refs: one in the index, one in `entry_before`.
        assert_eq!(Arc::strong_count(&entry_before), 2);
        let snapshot = cache.truncate_below(0);
        assert_eq!(snapshot.len(), 1);
        assert!(cache.lookup(7).is_none(), "page removed from index");
        // Snapshot + entry_before still alive.
        assert!(Arc::ptr_eq(&snapshot[0], &entry_before));
        assert_eq!(Arc::strong_count(&snapshot[0]), 2);
    }

    /// `wait_until_writeback_clear` returns immediately when
    /// `PG_WRITEBACK` is already clear. The assertion is that the
    /// call does not panic and exits without ever needing to park —
    /// host stub `WaitQueue::wait_while` is a no-op single-check, so
    /// a true predicate would *also* return without panic; the
    /// invariant we exercise is that the predicate is `is_writeback`,
    /// not some other mis-typed bit.
    #[test]
    fn wait_until_writeback_clear_no_op_when_bit_clear() {
        let p = make_stub(0);
        p.publish_uptodate_and_unlock();
        assert!(!p.is_writeback());
        p.wait_until_writeback_clear();
    }

    /// `wait_until_writeback_clear` is the symmetric park to
    /// `wait_until_unlocked` — predicate is `is_writeback`, not
    /// `is_locked`. This test exercises that the call observes the
    /// `PG_WRITEBACK` bit specifically: a page with `PG_LOCKED` set
    /// but `PG_WRITEBACK` clear must return immediately. The host
    /// stub's no-op `wait_while` collapses both predicates to the
    /// same observable behaviour, but the test still pins the
    /// expected predicate at the source level.
    #[test]
    fn wait_until_writeback_clear_ignores_locked_bit() {
        let p = make_stub(0);
        // The freshly-built stub has PG_LOCKED set (every other bit
        // clear). `wait_until_writeback_clear` must not park on
        // PG_LOCKED.
        assert!(p.is_locked());
        assert!(!p.is_writeback());
        p.wait_until_writeback_clear();
    }

    #[test]
    fn inode_id_is_value_type() {
        let a = InodeId::new(1, 2);
        let b = InodeId::new(1, 2);
        let c = InodeId::new(1, 3);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Copy semantics — taking by value does not move.
        let d = a;
        let _ = a;
        assert_eq!(d, b);
    }

    #[test]
    fn ops_field_round_trips_through_constructor() {
        // RFC 0007 §Inode-binding rule: `ops` is captured at
        // construction. Verify the constructor stores the same Arc
        // we passed in (Arc::ptr_eq) and that `ops()` returns a
        // clone pointing at the same allocation.
        let backing = crate::mem::aops::MemoryBackedOps::with_pages(2);
        let ops_in: Arc<dyn AddressSpaceOps> = backing.clone();
        let cache = PageCache::new(fake_inode_id(), 0, ops_in.clone());
        let ops_out = cache.ops();
        assert!(Arc::ptr_eq(&ops_in, &ops_out));
    }

    #[test]
    fn ops_dispatch_through_cache_handle() {
        // Once the page-fault path is wired (#739), the cache will
        // call `self.ops.readpage` from inside the install-then-fill
        // routine. Today the cache does not call into ops itself;
        // this test stands in for that future call by dispatching
        // through `cache.ops()` and verifying the round-trip.
        let backing = crate::mem::aops::MemoryBackedOps::with_pages(4);
        let cache = PageCache::new(fake_inode_id(), 0, backing.clone());
        let ops = cache.ops();
        let mut buf = [0u8; 4096];
        ops.readpage(2, &mut buf).expect("readpage ok");
        assert_eq!(buf[0], 2);
        assert_eq!(
            backing
                .readpage_calls
                .load(core::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn refcount_discipline_arc_clones_independent_of_dirty() {
        // RFC 0007 §Refcount discipline: an in-flight fault clones
        // the Arc (strong+1) before installing its PTE. Eviction
        // gates on `Arc::strong_count > 1`. We model the in-flight
        // clone here without involving mem::refcount (that's the
        // PTE-side counter) and verify the count moves as the RFC
        // requires.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        // After publish, only the cache index and our local `stub`
        // hold strong refs. That's strong_count == 2.
        assert_eq!(Arc::strong_count(&stub), 2);

        // Simulate an in-flight fault cloning out of the index.
        let in_flight = cache.lookup(0).expect("indexed");
        assert!(Arc::ptr_eq(&in_flight, &stub));
        assert_eq!(Arc::strong_count(&stub), 3);

        // Drop the in-flight clone — strong_count returns to 2.
        drop(in_flight);
        assert_eq!(Arc::strong_count(&stub), 2);
    }

    // --- ra_state heuristic --------------------------------------------

    #[test]
    fn ra_state_cold_inode_returns_zero_window() {
        // RFC 0007 §Performance Considerations (readahead): a fresh
        // inode that has never seen a miss observes 0-page read-ahead
        // until a streak develops. This is the cold-execve guarantee.
        let cache = fresh_cache();
        let initial = cache.ra_state();
        assert_eq!(initial.last_pgoff, None);
        assert_eq!(initial.hit_streak, 0);
        assert_eq!(initial.mode, RaMode::Normal);
        // First-ever miss: window is 0, streak becomes 1.
        let window = cache.note_miss(0);
        assert_eq!(window, 0);
        let after = cache.ra_state();
        assert_eq!(after.last_pgoff, Some(0));
        assert_eq!(after.hit_streak, 1);
    }

    #[test]
    fn ra_state_sequential_run_ramps_exponentially() {
        // First three misses: streak goes 1, 2, 3. Window pattern is
        // 0, 4, 8. The first miss is cold, the second is the first
        // observed sequential adjacency (streak == 2 ⇒ 2^2 == 4), the
        // third tops out at min(2^3, 8) == 8.
        let cache = fresh_cache();
        assert_eq!(cache.note_miss(10), 0);
        assert_eq!(cache.note_miss(11), 4);
        assert_eq!(cache.note_miss(12), 8);
        // Subsequent sequential misses stay capped at RA_MAX_PAGES.
        assert_eq!(cache.note_miss(13), RA_MAX_PAGES);
        assert_eq!(cache.note_miss(14), RA_MAX_PAGES);
        assert_eq!(cache.ra_state().hit_streak, 5);
    }

    #[test]
    fn ra_state_non_sequential_miss_resets_streak() {
        // Build up a streak, then jump to a non-adjacent pgoff. The
        // streak hard-resets to 1 (the just-noted miss) and the
        // window returns to 0.
        let cache = fresh_cache();
        cache.note_miss(0);
        cache.note_miss(1);
        cache.note_miss(2);
        assert!(cache.ra_state().hit_streak >= 3);

        let after_jump = cache.note_miss(100);
        assert_eq!(after_jump, 0);
        let st = cache.ra_state();
        assert_eq!(st.hit_streak, 1);
        assert_eq!(st.last_pgoff, Some(100));

        // Re-establishing a sequential run from the new position
        // ramps from scratch (the cold-streak rules apply afresh).
        assert_eq!(cache.note_miss(101), 4);
        assert_eq!(cache.note_miss(102), 8);
    }

    #[test]
    fn ra_state_backwards_miss_treated_as_non_sequential() {
        // Reading backwards is *not* the sequential pattern the
        // heuristic protects. A miss at pgoff < last_pgoff resets the
        // streak rather than ramping.
        let cache = fresh_cache();
        cache.note_miss(10);
        cache.note_miss(11);
        cache.note_miss(12);
        let backwards = cache.note_miss(11);
        assert_eq!(backwards, 0);
        assert_eq!(cache.ra_state().hit_streak, 1);
    }

    #[test]
    fn ra_state_repeated_pgoff_treated_as_non_sequential() {
        // Re-faulting the same pgoff (e.g. the abandon-then-retry
        // path) is not a streak-extending event: it does not satisfy
        // `pgoff == last_pgoff + 1`. The streak resets.
        let cache = fresh_cache();
        cache.note_miss(7);
        cache.note_miss(8);
        let repeat = cache.note_miss(8);
        assert_eq!(repeat, 0);
        assert_eq!(cache.ra_state().hit_streak, 1);
    }

    #[test]
    fn ra_state_advise_sequential_jumps_to_cap() {
        // POSIX_FADV_SEQUENTIAL / MADV_SEQUENTIAL: the very first
        // miss observes RA_MAX_PAGES regardless of streak.
        let cache = fresh_cache();
        cache.set_ra_mode(RaMode::Sequential);
        assert_eq!(cache.note_miss(50), RA_MAX_PAGES);
        // Even a non-sequential follow-up keeps the cap (the hint is
        // sticky).
        assert_eq!(cache.note_miss(2_000), RA_MAX_PAGES);
    }

    #[test]
    fn ra_state_advise_random_disables_readahead() {
        // POSIX_FADV_RANDOM / MADV_RANDOM: 0 pages read-ahead
        // regardless of streak, even for adjacent misses.
        let cache = fresh_cache();
        cache.set_ra_mode(RaMode::Random);
        assert_eq!(cache.note_miss(0), 0);
        assert_eq!(cache.note_miss(1), 0);
        assert_eq!(cache.note_miss(2), 0);
        assert_eq!(cache.note_miss(3), 0);
        // Sticky — a long sequential run does not flip back to
        // Normal heuristic on its own.
        for p in 4..32 {
            assert_eq!(cache.note_miss(p), 0);
        }
    }

    #[test]
    fn ra_state_mode_round_trips() {
        // Switching modes preserves the documented streak resets:
        // Sequential primes streak to cap; Random/Normal zero it.
        let cache = fresh_cache();
        cache.note_miss(0);
        cache.note_miss(1);
        cache.set_ra_mode(RaMode::Sequential);
        assert_eq!(cache.ra_state().hit_streak, RA_MAX_PAGES);
        cache.set_ra_mode(RaMode::Random);
        assert_eq!(cache.ra_state().hit_streak, 0);
        cache.set_ra_mode(RaMode::Normal);
        assert_eq!(cache.ra_state().hit_streak, 0);
        assert_eq!(cache.ra_state().mode, RaMode::Normal);
    }

    #[test]
    fn ra_state_execve_like_fault_stream_observes_no_readahead() {
        // RFC 0007 blocking-finding *Performance B2*: an execve fault
        // stream — _start, then a few scattered text pages, then
        // PLT/GOT pokes — must not pay the 8-page read-ahead tax. We
        // model that as: page 0 (cold), then a smattering of
        // non-adjacent pages. Window must stay 0 throughout.
        let cache = fresh_cache();
        let stream = [0u64, 7, 12, 5, 64, 2, 9];
        for p in stream {
            assert_eq!(
                cache.note_miss(p),
                0,
                "execve-like fault at pgoff {p} must not trigger read-ahead",
            );
        }
    }

    #[test]
    fn ra_state_window_caps_at_ra_max_pages() {
        // Synthesise a long sequential run and verify the saturating
        // shift never exceeds RA_MAX_PAGES. (The cap is the hard
        // guard the per-miss I/O fan-out depends on.)
        let cache = fresh_cache();
        let mut last_window = 0;
        for p in 0..32u64 {
            let w = cache.note_miss(p);
            assert!(w <= RA_MAX_PAGES, "window {w} exceeded cap");
            last_window = w;
        }
        // The tail of a long sequential run is pinned at the cap.
        assert_eq!(last_window, RA_MAX_PAGES);
    }

    #[test]
    fn ra_state_window_for_streak_pure_function() {
        // The pure helper used by note_miss — direct unit test on the
        // sequence so a future refactor can't silently change it.
        assert_eq!(RaState::window_for_streak(0), 0);
        assert_eq!(RaState::window_for_streak(1), 0);
        assert_eq!(RaState::window_for_streak(2), 4);
        assert_eq!(RaState::window_for_streak(3), 8);
        assert_eq!(RaState::window_for_streak(4), 8);
        assert_eq!(RaState::window_for_streak(31), RA_MAX_PAGES);
        // Saturating-shl path covers extreme inputs without panicking.
        assert_eq!(RaState::window_for_streak(u32::MAX), RA_MAX_PAGES);
    }

    // --- RFC 0007 §Refcount discipline — eviction-gate matrix --------
    //
    // These tests model the two independent counters the RFC mandates:
    //
    //   - `mem::refcount::get(phys)` — counts (1 cache-own) + (N
    //     installed PTEs). Bumped on PTE install / decremented on PTE
    //     teardown.
    //   - `Arc::strong_count(&CachePage)` — counts (1 cache index) +
    //     (N in-flight `Arc::clone`s held by faulters that have not
    //     yet decided whether to install a PTE) + (writeback daemon's
    //     snapshot, if any).
    //
    // Eviction (#740 — not yet merged) must check **both**:
    //
    //   - `Arc::strong_count(&CachePage) == 1` rules out an in-flight
    //     fault that may yet bump `mem::refcount` (RFC 0007 §Refcount
    //     discipline).
    //   - `mem::refcount(phys) <= 1` rules out a still-installed PTE.
    //
    // The two predicates are non-overlapping by design — neither
    // subsumes the other. These tests pin the predicates so a
    // future eviction implementation cannot silently regress to a
    // single-counter check.

    /// Pure predicate the future eviction policy will gate on. Passes
    /// only when **both** disciplines say the page is safe to drop:
    /// the cache index is the sole `Arc<CachePage>` strong holder
    /// **and** the per-frame refcount is at the cache's own slot
    /// (nothing has installed a PTE).
    ///
    /// This is the same predicate `evict()` will run; pinning it here
    /// as a pure function lets the test matrix below cover every
    /// combination of (strong_count, frame_refcount) without dragging
    /// in the not-yet-merged eviction control flow.
    fn eviction_safe(stub: &Arc<CachePage>, frame_refcount: u16) -> bool {
        Arc::strong_count(stub) == 1 && frame_refcount <= 1
    }

    /// Phys address used by the eviction-gate-matrix tests when they
    /// drive the `mem::refcount::*_in` slot helpers. The page-cache
    /// test harness's own `fake_phys()` deliberately picks values at
    /// `MAX_PHYS_BYTES` so they cannot collide with a real allocator
    /// hand-out — but that places them outside the refcount table.
    /// These tests want both: a stable `CachePage` Arc *and* a
    /// refcount slot keyed against the same notional frame. We use
    /// `0x1000` (the first refcount slot) for the host-only refcount
    /// table; the cache itself never dereferences `phys`.
    const TEST_REFCOUNT_PHYS: u64 = 0x1000;

    #[test]
    fn eviction_gate_blocks_when_pte_installed() {
        // PTE-installed-only: the cache index holds the sole Arc
        // (strong_count == 1) but `mem::refcount` shows a PTE is
        // mapped (== 2 = cache + 1 PTE). RFC 0007 §Refcount
        // discipline: eviction blocks on the frame-refcount check
        // even though no in-flight clone exists.
        let cache = fresh_cache();
        match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p.publish_uptodate_and_unlock(),
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        // Outer Arc dropped at end of match — cache index is now the
        // sole strong holder. The real evictor borrows from the
        // BTreeMap (no Arc clone), so its observed `strong_count` is
        // 1 in this state. Mirror that with a borrow under
        // `cache.inner`.
        let strong_borrow = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        assert_eq!(strong_borrow, 1, "borrow-only access does not bump strong");

        // Frame refcount: 2 = cache(1) + PTE(1). Use the host-test
        // refcount-slot helpers.
        let slots: alloc::vec::Vec<core::sync::atomic::AtomicU16> = (0..4)
            .map(|_| core::sync::atomic::AtomicU16::new(0))
            .collect();
        crate::mem::refcount::init_on_alloc_in(&slots, TEST_REFCOUNT_PHYS);
        crate::mem::refcount::inc_refcount_in(&slots, TEST_REFCOUNT_PHYS); // PTE bump
        let frame_rc = crate::mem::refcount::page_refcount_in(&slots, TEST_REFCOUNT_PHYS)
            .load(core::sync::atomic::Ordering::Relaxed);
        assert_eq!(frame_rc, 2, "frame refcount = cache + PTE");

        // The strong-count axis says safe (1), the frame-refcount
        // axis says blocked (2). Eviction must respect *both* — RFC
        // 0007 §Refcount discipline: "neither subsumes the other."
        assert!(
            !(strong_borrow == 1 && frame_rc <= 1),
            "evictor must refuse: PTE still mapped",
        );
    }

    #[test]
    fn eviction_gate_blocks_when_in_flight_clone_held() {
        // In-flight fault has cloned the Arc out of the index but has
        // not yet bumped `mem::refcount` (still mid-resolution). The
        // frame refcount is the cache's own (== 1); the strong count
        // is > 1. RFC 0007 §Refcount discipline: eviction blocks on
        // the strong-count check even though the frame refcount is
        // clear.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();

        // `cache.lookup` returns a fresh `Arc::clone` — exactly what
        // the slow-path fault hot path does (RFC 0007 §Refcount
        // discipline, fault hot path code block).
        let in_flight = cache.lookup(0).expect("indexed");
        assert!(Arc::ptr_eq(&in_flight, &stub));

        // Frame refcount: 1 = cache only (no PTE installed yet).
        let frame_rc = 1u16;

        // Strong count snapshot from inside the index borrow — same
        // shape the evictor would observe.
        let strong_borrow = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        // 3 = cache index + outer `stub` + `in_flight`.
        assert_eq!(strong_borrow, 3);

        assert!(
            !eviction_safe(&in_flight, frame_rc),
            "evictor must refuse: in-flight Arc clone outstanding",
        );

        // Drop the in-flight clone; eviction gate becomes per-strong
        // satisfiable (still blocked here only because outer `stub`
        // holds another clone).
        drop(in_flight);
        let strong_after_drop = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        assert_eq!(strong_after_drop, 2, "outer `stub` is the +1");
    }

    #[test]
    fn eviction_gate_passes_when_only_cache_holds_arc_and_no_pte() {
        // Cache-own only: the cache index is the sole Arc holder,
        // `mem::refcount == 1` (cache's own slot, no PTE). Both
        // predicates pass; the future evictor may proceed (frame
        // becomes droppable, will eventually `frame::put`). This is
        // the only combination on the matrix that is safe.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        // Use a refcount-table-valid phys for the host helpers
        // (`stub.phys` is a fake_phys() value at the MAX_PHYS_BYTES
        // boundary chosen so it can never collide with a real
        // allocator hand-out; the refcount slot table refuses it).
        let phys = TEST_REFCOUNT_PHYS;
        drop(stub);

        let slots: alloc::vec::Vec<core::sync::atomic::AtomicU16> = (0..4)
            .map(|_| core::sync::atomic::AtomicU16::new(0))
            .collect();
        // Cache's own ref is `init_on_alloc_in` (== 1) — no PTE bumps.
        crate::mem::refcount::init_on_alloc_in(&slots, phys);
        let frame_rc = crate::mem::refcount::page_refcount_in(&slots, phys)
            .load(core::sync::atomic::Ordering::Relaxed);

        let strong_borrow = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };

        assert_eq!(strong_borrow, 1, "cache index is the sole strong holder");
        assert_eq!(frame_rc, 1, "frame refcount = cache only");

        // Synthesise the borrow-style strong_count for the closure
        // form (we cannot pass a borrowed Arc-not-clone to a generic
        // helper, so we recombine the predicates inline here).
        assert!(
            strong_borrow == 1 && frame_rc <= 1,
            "evictor may proceed: cache-own only",
        );
    }

    #[test]
    fn eviction_gate_blocks_when_both_pte_and_in_flight_clone() {
        // Both axes: the dominant case — a fault has resolved into a
        // PTE install (`mem::refcount > 1`) AND another concurrent
        // fault is mid-resolution (`Arc::strong_count > 1`). Eviction
        // blocks on either; here it blocks on both, so the predicate
        // must return false regardless of which check the evictor
        // runs first.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        // Use a refcount-table-valid phys for the host helpers
        // (`stub.phys` is a fake_phys() value at the MAX_PHYS_BYTES
        // boundary chosen so it can never collide with a real
        // allocator hand-out; the refcount slot table refuses it).
        let phys = TEST_REFCOUNT_PHYS;

        let slots: alloc::vec::Vec<core::sync::atomic::AtomicU16> = (0..4)
            .map(|_| core::sync::atomic::AtomicU16::new(0))
            .collect();
        crate::mem::refcount::init_on_alloc_in(&slots, phys);
        crate::mem::refcount::inc_refcount_in(&slots, phys); // PTE
        let frame_rc = crate::mem::refcount::page_refcount_in(&slots, phys)
            .load(core::sync::atomic::Ordering::Relaxed);

        // Drop outer Arc to mirror the "PTE owns the bump, not us"
        // shape, then re-clone for the in-flight observer.
        drop(stub);
        let in_flight = cache.lookup(0).unwrap();

        assert!(!eviction_safe(&in_flight, frame_rc));
    }

    #[test]
    fn eviction_gate_writeback_snapshot_blocks_eviction() {
        // The writeback daemon's `snapshot_dirty()` clones the Arc
        // out of the index (RFC 0007 §`PageCache` writeback snapshot
        // pattern). While the snapshot is alive, eviction must
        // block — the daemon may still call `writepage` against the
        // page contents. This is the exact reason `snapshot_dirty`
        // returns `Vec<(u64, Arc<CachePage>)>` rather than a
        // borrowing iterator.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        cache.mark_page_dirty(0);
        drop(stub);

        // Pretend the writeback daemon just snapshotted.
        let snap = cache.snapshot_dirty();
        assert_eq!(snap.len(), 1);

        // Strong count from the cache's perspective is 2 (index +
        // snapshot Arc). Eviction blocks even though we hold no
        // in-flight fault clone.
        let strong_borrow = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        assert_eq!(strong_borrow, 2, "snapshot is the +1");
        assert!(
            !eviction_safe(&snap[0].1, 1),
            "evictor must refuse while writeback snapshot is alive",
        );

        // After the daemon completes and drops the snapshot, the
        // strong count returns to 1 — eviction may proceed (for the
        // strong-count axis; the frame-refcount axis is independent).
        drop(snap);
        let strong_after_snap = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        assert_eq!(strong_after_snap, 1);
    }

    #[test]
    fn refcount_disciplines_are_independent() {
        // RFC 0007 §Refcount discipline is explicit: the two counters
        // are *non-overlapping*. Mutations to one must not affect the
        // other. Verify by exercising the strong count without
        // touching `mem::refcount`, and vice versa.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        // Use a refcount-table-valid phys for the host helpers
        // (`stub.phys` is a fake_phys() value at the MAX_PHYS_BYTES
        // boundary chosen so it can never collide with a real
        // allocator hand-out; the refcount slot table refuses it).
        let phys = TEST_REFCOUNT_PHYS;

        let slots: alloc::vec::Vec<core::sync::atomic::AtomicU16> = (0..4)
            .map(|_| core::sync::atomic::AtomicU16::new(0))
            .collect();
        crate::mem::refcount::init_on_alloc_in(&slots, phys);

        // Bump strong count via lookups; mem::refcount stays at 1.
        let a = cache.lookup(0).unwrap();
        let b = cache.lookup(0).unwrap();
        let c = cache.lookup(0).unwrap();
        assert_eq!(
            crate::mem::refcount::page_refcount_in(&slots, phys)
                .load(core::sync::atomic::Ordering::Relaxed),
            1,
            "strong-count bumps must not affect frame refcount",
        );
        drop((a, b, c));

        // Bump mem::refcount via PTE simulation; strong count stays.
        crate::mem::refcount::inc_refcount_in(&slots, phys);
        crate::mem::refcount::inc_refcount_in(&slots, phys);
        let strong_borrow = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        // outer `stub` + index = 2 (we still hold `stub`).
        assert_eq!(
            strong_borrow, 2,
            "frame-refcount bumps must not affect strong"
        );
        assert_eq!(
            crate::mem::refcount::page_refcount_in(&slots, phys)
                .load(core::sync::atomic::Ordering::Relaxed),
            3,
        );
    }

    // --- RFC 0007 §Lock-order ladder — split-lock discipline ----------

    #[test]
    fn install_or_get_drops_inner_before_returning_outcome() {
        // Split-lock discipline (RFC 0007 §Split-lock discipline):
        // `install_or_get` takes `cache.inner` only across the
        // index check + insert. Once it returns, the mutex is free
        // for any other slow-path observer. We model that by
        // calling install_or_get and verifying inner is acquirable
        // immediately after.
        let cache = fresh_cache();
        let outcome = cache.install_or_get(0, || make_stub(0));
        assert!(matches!(outcome, InstallOutcome::InstalledNew(_)));
        // If install_or_get had retained the guard, this lock() would
        // block forever (host stub uses spin::Mutex; `try_lock` is
        // the deadlock-safe probe).
        let guard = cache.inner.try_lock();
        assert!(
            guard.is_some(),
            "cache.inner must be free post install_or_get"
        );
    }

    #[test]
    fn lookup_drops_inner_before_returning() {
        // Same split-lock discipline applies to the read side: the
        // `lookup` fast path holds `cache.inner` only across
        // `BTreeMap::get`, then drops the guard before handing the
        // `Arc<CachePage>` clone back. A caller that hangs onto the
        // returned Arc must still see `cache.inner` as releasable.
        let cache = fresh_cache();
        cache.install_or_get(0, || make_stub(0));
        let _hit = cache.lookup(0);
        let guard = cache.inner.try_lock();
        assert!(guard.is_some(), "cache.inner must be free post lookup");
    }

    #[test]
    fn snapshot_dirty_drops_inner_before_returning() {
        // The writeback daemon path: `snapshot_dirty` collects under
        // `cache.inner`, then returns. The mutex must be free before
        // the daemon iterates the snapshot calling `writepage` (which
        // is RFC 0007 §Lock-order: `cache.inner` is **never** held
        // across `writepage`).
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        cache.mark_page_dirty(0);

        let snap = cache.snapshot_dirty();
        assert_eq!(snap.len(), 1);
        // `cache.inner` must be free even while the snapshot is held.
        let guard = cache.inner.try_lock();
        assert!(
            guard.is_some(),
            "cache.inner must be free while writeback snapshot is alive",
        );
    }

    #[test]
    fn mark_page_dirty_drops_inner_before_returning() {
        // The Shared-write fault dirty-publish: the bit-set + index
        // enrollment commit under one critical section, then the
        // mutex releases. Subsequent fast-path lookups on unrelated
        // pgoffs must not block on a leftover guard.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        assert!(cache.mark_page_dirty(0));
        let guard = cache.inner.try_lock();
        assert!(guard.is_some());
    }

    // --- writeback_complete_wq plumbing (issue #757) -------------------
    //
    // These tests verify the structural plumbing of the new per-cache
    // wait queue: the wq exists on the cache, it is attached to every
    // installed `CachePage`, `end_writeback` and `Drop` both kick it.
    // The host stub's `WaitQueue::notify_count()` lets us see the
    // wakes even though the host has no real parked tasks; the
    // bare-metal park-and-wake protocol is exercised by the QEMU
    // integration test `writeback_complete_wq.rs`.

    #[test]
    fn cache_owns_writeback_complete_wq() {
        let cache = fresh_cache();
        let wq = cache.writeback_complete_wq();
        // Identical Arc on every call (no fresh allocation per
        // accessor) — RFC 0007 §Eviction liveness: a single per-cache
        // queue is the wake fan-in for direct reclaim.
        let wq2 = cache.writeback_complete_wq();
        assert!(Arc::ptr_eq(&wq, &wq2));
    }

    #[test]
    fn install_or_get_attaches_writeback_wq_to_stub() {
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        let attached = stub
            .parent_wb_wq
            .get()
            .expect("install_or_get must attach the cache's wb wq");
        assert!(Arc::ptr_eq(attached, &cache.writeback_complete_wq()));
    }

    #[test]
    fn freestanding_stub_has_no_wb_wq() {
        // A stub built with `CachePage::new_locked` directly (without
        // going through `install_or_get`) has no parent wq. This is
        // the path host unit tests for the per-page state machine
        // take; the absence of an attached wq must keep their
        // `end_writeback` / `Drop` paths working as no-ops.
        let stub = make_stub(0);
        assert!(stub.parent_wb_wq.get().is_none());
        // Calling end_writeback / dropping is a non-panicking no-op.
        stub.publish_uptodate_and_unlock();
        stub.begin_writeback();
        stub.end_writeback();
        drop(stub); // exercises the Drop kick on a freestanding page
    }

    #[test]
    fn end_writeback_kicks_cache_wq() {
        // PG_WRITEBACK clear must wake the per-cache wq. Host stub
        // counts the wake; the real bare-metal queue's `notify_all`
        // does the same plus actually waking parkers.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        let wq = cache.writeback_complete_wq();
        let before = wq.notify_count();
        stub.begin_writeback();
        // begin_writeback does NOT kick the wq (the wake is reserved
        // for completion).
        assert_eq!(wq.notify_count(), before);
        stub.end_writeback();
        // end_writeback must have fired exactly one wake on the wq.
        assert_eq!(
            wq.notify_count(),
            before + 1,
            "end_writeback must kick the cache's writeback_complete_wq",
        );
    }

    #[test]
    fn cachepage_drop_kicks_cache_wq() {
        // Drop kick: the lost-wakeup defence — a writeback handle
        // dropped without `end_writeback` must still wake direct
        // reclaim. We model this by removing the cache's index entry
        // and dropping our own outer Arc, taking strong_count to 0.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        let wq = cache.writeback_complete_wq();
        let before = wq.notify_count();
        // Drop the index strong-ref so our outer `stub` is the sole
        // holder; then drop `stub` and observe the wake.
        cache.inner.lock().pages.remove(&0);
        // strong_count is now 1 (just our `stub`). Dropping fires Drop.
        drop(stub);
        assert_eq!(
            wq.notify_count(),
            before + 1,
            "CachePage::Drop must kick the cache's writeback_complete_wq",
        );
    }

    #[test]
    fn end_writeback_and_drop_each_fire_independent_kicks() {
        // The two wake sources are independent: a page that
        // *completes* writeback (one kick) and is later evicted from
        // the cache and dropped (second kick) produces two
        // notifications, not one. RFC 0007 §Eviction liveness item 4
        // — "per-event retry": each wake gives the parked faulter
        // one CLOCK-Pro retry opportunity.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        let wq = cache.writeback_complete_wq();
        let before = wq.notify_count();

        stub.begin_writeback();
        stub.end_writeback();
        cache.inner.lock().pages.remove(&0);
        drop(stub);

        assert_eq!(
            wq.notify_count(),
            before + 2,
            "end_writeback and Drop must each kick the wq once",
        );
    }

    #[test]
    fn writeback_wq_outlives_cache_for_alive_pages() {
        // The `writeback_complete_wq` is held via `Arc`, so a
        // surviving `CachePage` clone keeps the wq alive even after
        // the parent `PageCache` itself drops. The Drop notify on
        // such a clone is a harmless no-op against an empty queue —
        // there is no parked task on it because the only consumer
        // (CLOCK-Pro reclaim) parks via `cache.wait_writeback_complete`
        // and cannot park if the cache itself is gone.
        let cache = fresh_cache();
        let stub = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        stub.publish_uptodate_and_unlock();
        // Snapshot the wq Arc *before* dropping the cache so we can
        // observe its notify_count after the cache is gone.
        let wq = cache.writeback_complete_wq();
        let before = wq.notify_count();
        drop(cache); // index entry's strong-ref goes away.
                     // `stub` still holds an Arc on the wq via parent_wb_wq.
        drop(stub);
        // The Drop kick fires against the surviving wq.
        assert_eq!(
            wq.notify_count(),
            before + 1,
            "Drop kick must fire even after the parent cache is gone",
        );
    }

    #[test]
    fn wait_writeback_complete_invokes_predicate() {
        // The convenience park: just verifies the predicate is
        // called. The real park/wake handshake is QEMU-only.
        let cache = fresh_cache();
        let mut calls = 0;
        cache.wait_writeback_complete(|| {
            calls += 1;
            false // returns immediately on host stub
        });
        assert!(calls >= 1);
    }

    // --- CLOCK-Pro eviction (issue #740) -----------------------------------

    /// Helper: install and publish a page so it is in the UPTODATE,
    /// non-LOCKED, non-DIRTY state the evictor can act on.
    fn install_and_publish(cache: &PageCache, pgoff: u64) -> Arc<CachePage> {
        let stub = match cache.install_or_get(pgoff, || make_stub(pgoff)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => panic!("expected InstalledNew"),
        };
        stub.publish_uptodate_and_unlock();
        stub
    }

    #[test]
    fn evict_if_needed_under_cap_is_noop() {
        let cache = fresh_cache_capped(4);
        install_and_publish(&cache, 0);
        install_and_publish(&cache, 1);
        // 2 pages, cap is 4 — no eviction needed.
        assert_eq!(cache.evict_if_needed(), Ok(()));
        assert!(cache.lookup(0).is_some());
        assert!(cache.lookup(1).is_some());
    }

    #[test]
    fn evict_if_needed_unlimited_cache_is_noop() {
        // max_pages == 0 means unlimited.
        let cache = fresh_cache();
        for p in 0..10 {
            install_and_publish(&cache, p);
        }
        assert_eq!(cache.evict_if_needed(), Ok(()));
    }

    #[test]
    fn clock_pro_evicts_cold_unreferenced_page() {
        // cap=2, install 2 pages, then ask for eviction. The sweep
        // should find a cold, unreferenced victim and evict it.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        // Drop external Arcs so strong_count reaches 1 (cache only).
        drop(p0);
        drop(p1);
        // Clear reference bits so the sweep can evict.
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        assert_eq!(cache.evict_if_needed(), Ok(()));
        // One page was evicted, one remains.
        let inner = cache.inner.lock();
        assert_eq!(inner.pages.len(), 1);
        assert_eq!(inner.non_resident.len(), 1);
    }

    #[test]
    fn clock_pro_skips_pinned_page() {
        // RFC 0007 §Eviction: skip any page with
        // `Arc::strong_count > 1`.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        // Clear reference bits.
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // Hold onto both Arcs — strong_count is 2 for each (cache + us).
        // The sweep should find no victim because both are pinned.
        let result = cache.evict_if_needed();
        assert_eq!(result, Err(EvictError::NoVictim));
        // Both pages are still indexed.
        assert!(cache.lookup(0).is_some());
        assert!(cache.lookup(1).is_some());
        drop(p0);
        drop(p1);
    }

    #[test]
    fn clock_pro_skips_dirty_page() {
        // RFC 0007 §Eviction: skip PG_DIRTY.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        cache.mark_page_dirty(0);
        cache.mark_page_dirty(1);
        drop(p0);
        drop(p1);
        // Clear reference bits.
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // All pages dirty — no victim.
        assert_eq!(cache.evict_if_needed(), Err(EvictError::NoVictim));
    }

    #[test]
    fn clock_pro_skips_writeback_page() {
        // RFC 0007 §Eviction: skip PG_WRITEBACK.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        p0.begin_writeback();
        p1.begin_writeback();
        drop(p0);
        drop(p1);
        // Clear reference bits.
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        assert_eq!(cache.evict_if_needed(), Err(EvictError::NoVictim));
    }

    #[test]
    fn clock_pro_skips_locked_page() {
        // RFC 0007 §Eviction: skip PG_LOCKED.
        let cache = fresh_cache_capped(2);
        // Install but do NOT publish (remains PG_LOCKED).
        let p0 = match cache.install_or_get(0, || make_stub(0)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        let p1 = install_and_publish(&cache, 1);
        drop(p0);
        drop(p1);
        // Clear reference bits.
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // page 0 is locked — skip; page 1 is cold + unreferenced → evict.
        assert_eq!(cache.evict_if_needed(), Ok(()));
        // Page 0 survives (locked), page 1 was evicted.
        assert!(cache.lookup(0).is_some());
        assert!(cache.lookup(1).is_none());
    }

    #[test]
    fn clock_pro_skips_in_flight_page() {
        // RFC 0007 §Eviction: skip PG_IN_FLIGHT.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        p0.mark_in_flight();
        drop(p0);
        drop(p1);
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // page 0 in-flight — skip; page 1 → evict.
        assert_eq!(cache.evict_if_needed(), Ok(()));
        assert!(cache.lookup(0).is_some());
        assert!(cache.lookup(1).is_none());
    }

    #[test]
    fn clock_pro_promoted_ghost_enters_hot() {
        // CLOCK-Pro: a non-resident ghost hit re-enters as Hot.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        drop(p0);
        drop(p1);
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // Evict one page (say pgoff 0 — the hand starts at 0).
        assert_eq!(cache.evict_if_needed(), Ok(()));
        let evicted_pgoff = if cache.lookup(0).is_none() { 0 } else { 1 };
        // Now the evicted pgoff is in the non_resident queue.
        {
            let inner = cache.inner.lock();
            assert!(inner.non_resident.contains(&evicted_pgoff));
        }
        // Re-install the evicted pgoff — it should enter as Hot.
        let p_new = install_and_publish(&cache, evicted_pgoff);
        drop(p_new);
        {
            let inner = cache.inner.lock();
            assert_eq!(
                inner.classes.get(&evicted_pgoff),
                Some(&ClockClass::Hot),
                "re-referenced ghost must be promoted to Hot",
            );
            // Ghost should be removed from non_resident.
            assert!(!inner.non_resident.contains(&evicted_pgoff));
        }
    }

    #[test]
    fn clock_pro_hot_page_survives_one_sweep() {
        // Hot pages must survive one reference-bit sweep before they
        // can be evicted (demoted to cold first, then evicted on the
        // next cold sweep).
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        drop(p0);
        drop(p1);
        // Force page 0 to Hot classification.
        {
            let mut inner = cache.inner.lock();
            inner.classes.insert(0, ClockClass::Hot);
            // Clear all reference bits.
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // Eviction with page 0 Hot + unreferenced → demote to Cold,
        // then evict page 1 (which is Cold + unreferenced).
        assert_eq!(cache.evict_if_needed(), Ok(()));
        assert!(cache.lookup(0).is_some(), "hot page survives sweep");
        assert!(cache.lookup(1).is_none(), "cold page evicted");
        // Page 0 should now be Cold (demoted).
        {
            let inner = cache.inner.lock();
            assert_eq!(inner.classes.get(&0), Some(&ClockClass::Cold));
        }
    }

    #[test]
    fn clock_pro_referenced_cold_promoted_to_hot() {
        // A cold page with its reference bit set gets promoted to hot.
        let cache = fresh_cache_capped(3);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        let p2 = install_and_publish(&cache, 2);
        drop(p0);
        drop(p1);
        drop(p2);
        // Leave page 0 referenced (simulating a cache hit); clear
        // pages 1 and 2.
        {
            let inner = cache.inner.lock();
            let pg0 = inner.pages.get(&0).unwrap();
            pg0.clock_ref
                .store(true, core::sync::atomic::Ordering::Relaxed);
            let pg1 = inner.pages.get(&1).unwrap();
            pg1.clock_ref
                .store(false, core::sync::atomic::Ordering::Relaxed);
            let pg2 = inner.pages.get(&2).unwrap();
            pg2.clock_ref
                .store(false, core::sync::atomic::Ordering::Relaxed);
        }
        // Evict: page 0 (cold + referenced) → promote to hot; page 1
        // (cold + unreferenced) → evict.
        assert_eq!(cache.evict_if_needed(), Ok(()));
        assert!(cache.lookup(0).is_some());
        {
            let inner = cache.inner.lock();
            assert_eq!(
                inner.classes.get(&0),
                Some(&ClockClass::Hot),
                "cold + referenced must be promoted to hot",
            );
        }
    }

    #[test]
    fn no_victim_returns_enomem() {
        // All pages pinned (strong_count > 1) — sweep returns NoVictim
        // (which the fault path maps to ENOMEM → SIGBUS).
        let cache = fresh_cache_capped(2);
        let _p0 = install_and_publish(&cache, 0);
        let _p1 = install_and_publish(&cache, 1);
        // Both pages pinned (our outer Arcs).
        assert_eq!(cache.evict_if_needed(), Err(EvictError::NoVictim));
    }

    #[test]
    fn evict_or_wait_succeeds_when_under_cap() {
        let cache = fresh_cache_capped(4);
        install_and_publish(&cache, 0);
        assert_eq!(cache.evict_or_wait(2000), Ok(()));
    }

    #[test]
    fn evict_or_wait_no_victim_after_cap_returns_enomem() {
        // All pages pinned — evict_or_wait must return NoVictim after
        // the bounded wait. On host stub the wait returns immediately.
        let cache = fresh_cache_capped(2);
        let _p0 = install_and_publish(&cache, 0);
        let _p1 = install_and_publish(&cache, 1);
        assert_eq!(cache.evict_or_wait(2000), Err(EvictError::NoVictim));
    }

    #[test]
    fn evict_or_wait_retry_after_unpin_succeeds() {
        // Simulates the "retry on each wake" path: first sweep fails
        // (all pages pinned), then we drop the pin on one page, and
        // the next sweep succeeds.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let _p1 = install_and_publish(&cache, 1);
        // Clear reference bits.
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // Drop p0 so it becomes unpinned (strong_count -> 1).
        drop(p0);
        // Now evict_or_wait should succeed: page 0 is evictable.
        assert_eq!(cache.evict_or_wait(2000), Ok(()));
    }

    #[test]
    fn evict_or_wait_zero_timeout_still_tries_once() {
        // A timeout of 0 should still try the initial sweep.
        let cache = fresh_cache_capped(2);
        let p0 = install_and_publish(&cache, 0);
        let p1 = install_and_publish(&cache, 1);
        drop(p0);
        drop(p1);
        {
            let inner = cache.inner.lock();
            for (_, page) in inner.pages.iter() {
                page.clock_ref
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }
        }
        assert_eq!(cache.evict_or_wait(0), Ok(()));
    }

    #[test]
    fn lookup_sets_clock_ref_on_hit() {
        let cache = fresh_cache();
        let stub = install_and_publish(&cache, 0);
        // Clear clock_ref manually.
        stub.clock_ref
            .store(false, core::sync::atomic::Ordering::Relaxed);
        drop(stub);
        // Lookup should set clock_ref.
        let hit = cache.lookup(0).unwrap();
        assert!(
            hit.clock_ref.load(core::sync::atomic::Ordering::Relaxed),
            "lookup must set clock_ref on cache hit",
        );
    }

    #[test]
    fn install_or_get_sets_clock_ref_and_cold_class() {
        let cache = fresh_cache();
        let stub = match cache.install_or_get(5, || make_stub(5)) {
            InstallOutcome::InstalledNew(p) => p,
            InstallOutcome::AlreadyPresent(_) => unreachable!(),
        };
        // Freshly installed → clock_ref = true, class = Cold.
        assert!(stub.clock_ref.load(core::sync::atomic::Ordering::Relaxed));
        let inner = cache.inner.lock();
        assert_eq!(inner.classes.get(&5), Some(&ClockClass::Cold));
        assert!(inner.clock_hand.is_some());
    }

    #[test]
    fn non_resident_ghost_bounded_by_max_pages() {
        let cache = fresh_cache_capped(2);
        // Install and evict 4 pages, each becoming a ghost.
        for i in 0..4u64 {
            let p = install_and_publish(&cache, i);
            drop(p);
        }
        // Clear reference bits for eviction.
        for _ in 0..4 {
            {
                let inner = cache.inner.lock();
                for (_, page) in inner.pages.iter() {
                    page.clock_ref
                        .store(false, core::sync::atomic::Ordering::Relaxed);
                }
            }
            let _ = cache.evict_if_needed();
        }
        // Ghost queue is bounded by max_pages (2).
        let inner = cache.inner.lock();
        assert!(
            inner.non_resident.len() <= 2,
            "non_resident ghost queue must be bounded by max_pages",
        );
    }
}
