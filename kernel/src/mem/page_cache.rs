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
//! - Read-ahead heuristic and `ra_state` (#741).
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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;

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
    }

    pub struct WaitQueue;

    impl WaitQueue {
        pub const fn new() -> Self {
            Self
        }
        pub fn notify_all(&self) {}
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

    /// Conclude writeback. Clears [`PG_WRITEBACK`] with `Release` and
    /// wakes every parked waiter (truncate parks here while
    /// `PG_WRITEBACK` is set).
    pub fn end_writeback(&self) {
        self.state.fetch_and(!PG_WRITEBACK, Ordering::Release);
        self.wait.notify_all();
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
}

impl PageCacheInner {
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            dirty: BTreeSet::new(),
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
/// VFS plumbing). The `ra_state` (#741) and `writeback_complete_wq`
/// (#740) fields are still deferred to their respective sibling
/// issues; the `ops` per-FS hook lands here (#737).
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
    pub ops: Arc<dyn AddressSpaceOps>,

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
        Self {
            ops,
            inner: BlockingMutex::new(PageCacheInner::new()),
            i_size: AtomicU64::new(i_size),
            inode_id,
            wb_err: AtomicU32::new(0),
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
    pub fn lookup(&self, pgoff: u64) -> Option<Arc<CachePage>> {
        self.inner.lock().pages.get(&pgoff).cloned()
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
        inner.pages.insert(pgoff, stub.clone());
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
                    // the index entry.
                    inner.dirty.remove(&pgoff);
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

    /// Atomically replace the `i_size` cap. Caller is responsible
    /// for any cache-index mutations the truncation requires; this
    /// helper handles only the size publish so the foundation tests
    /// can exercise it without depending on the truncation algorithm
    /// (which is part of #740).
    pub fn store_i_size(&self, new_size: u64) {
        self.i_size.store(new_size, Ordering::Release);
    }
}

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

    #[test]
    fn i_size_round_trips() {
        let cache = fresh_cache();
        assert_eq!(cache.i_size(), 0);
        cache.store_i_size(8192);
        assert_eq!(cache.i_size(), 8192);
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
}
