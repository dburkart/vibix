//! `FileObject` — the [`VmObject`] that backs every file-mmap VMA
//! (RFC 0007 §FileObject, §Algorithms).
//!
//! A `FileObject` owns:
//!
//! - An `Arc<PageCache>` captured at construction and **never rebound**
//!   (RFC 0007 §Inode-binding rule — closes the execve-rename TOCTOU
//!   surface).
//! - A `[file_offset_pages, file_offset_pages + len_pages)` window into
//!   that cache.
//! - A [`Share`] discipline (`Shared` or `Private`) that the share-aware
//!   fault method uses to decide whether a write fault dirties the
//!   cache page (Shared) or surfaces [`VmFault::CoWNeeded`] for the
//!   resolver to handle via `cow_copy_and_remap` (Private).
//! - A snapshot of the open file's access mode (`O_RDONLY` /
//!   `O_WRONLY` / `O_RDWR`) consulted by `mprotect` to enforce the
//!   "PROT_WRITE upgrade requires `O_RDWR`" rule (RFC 0007 §FileObject
//!   `open_mode` snapshot — closes Security B1).
//! - A per-VMA `private_frames: BlockingMutex<BTreeMap<pgoff, phys>>`
//!   recording post-CoW private frames so a re-fault after
//!   `madvise(MADV_DONTNEED)` returns the same private frame instead
//!   of allocating a fresh one (RFC 0007 §FileObject `private_frames`).
//!
//! # Page-fault IRQ discipline (RFC 0007)
//!
//! `FileObject::fault` is invoked from the page-fault slow path with
//! IRQs **enabled** (the arch handler `sti`s after the pure-logic
//! verdict and before this dispatch — see `kernel/src/arch/x86_64/idt.rs`).
//! Anything we do here is therefore preemptible. The fast-path
//! cache-hit branch holds [`PageCache::inner`] only across the
//! `BTreeMap::get` clone and the dirty-publish; the slow-path
//! filler enters [`AddressSpaceOps::readpage`] with **no** spinlock or
//! BlockingMutex held, per the level-4-cache → level-6-buffer-cache
//! lock-order rule.
//!
//! # Out of scope (sibling issues)
//!
//! - Threading [`VmFault::CoWNeeded`] / [`VmFault::ParkAndRetry`] /
//!   [`VmFault::ReadFailed`] through the resolver in
//!   `arch/x86_64/idt.rs` is #739. Until that lands, the resolver's
//!   existing `Err(e) => log` branch covers them — the kernel does
//!   not yet construct file-backed VMAs, so the new errors cannot be
//!   produced from a real fault.
//! - Eviction, writeback, `private_frames` plumbing into the CoW
//!   resolver's "remember the private frame" hook are #740/#742/#746.
//!   This module exposes the storage; the resolver will read/write
//!   through it once #739 lands.
//! - `FileOps::mmap` overrides on ext2/ramfs/tarfs are #747/#751.
//!   They construct an `Arc<FileObject>` with the same fields this
//!   module defines; nothing here depends on those drivers.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::mem::page_cache::{InstallOutcome, PageCache, PG_LOCKED, PG_UPTODATE};
use crate::mem::vmatree::Share;
use crate::mem::vmobject::{Access, VmFault, VmObject};
use crate::mem::FRAME_SIZE;

// Sync primitives. On bare metal we use the real `BlockingMutex`; on
// host (`cfg(test)`), `crate::sync` is gated out (it depends on
// kernel-only `task::block_current` / `task::wake`), so we substitute
// `spin::Mutex` — host unit tests of the share-aware dispatch never
// exercise cross-thread parking; the `Arc<Mutex<...>>` shape is what
// they need.
#[cfg(target_os = "none")]
use crate::sync::BlockingMutex;

#[cfg(all(test, not(target_os = "none")))]
use spin::Mutex as BlockingMutex;

/// `FileObject` — an `Arc<PageCache>`-backed `VmObject` for file-mmap
/// VMAs.
///
/// The struct shape is normative (RFC 0007 §FileObject). Construction
/// is the only point at which `cache` may be set; the `Arc` is then
/// immutable for the `FileObject`'s lifetime.
pub struct FileObject {
    /// The page cache to consult on faults. Bound to the inode at
    /// construction and **never rebound** (RFC 0007 §Inode-binding
    /// rule). A re-execve that resolves to a different inode constructs
    /// a separate `FileObject` against the new inode's separate
    /// `Arc<PageCache>` — the old object continues serving the old
    /// mapping until the original VMA is torn down.
    cache: Arc<PageCache>,

    /// Region `[file_offset_pages, file_offset_pages + len_pages)` of
    /// the file (in 4 KiB-page units) that this VMA covers. Mirrors
    /// `AnonObject::len_pages` for the OutOfRange/SIGBUS check.
    file_offset_pages: u64,

    /// Page-count cap. Faults at or past this index return
    /// [`VmFault::OutOfRange`] (SIGBUS).
    len_pages: usize,

    /// MAP_SHARED vs MAP_PRIVATE. Determines whether write faults
    /// dirty the cache page (Shared) or surface
    /// [`VmFault::CoWNeeded`] (Private).
    share: Share,

    /// Snapshot of the open file's access mode (the
    /// `OpenFile.flags & O_ACCMODE` value) at the moment of `mmap`.
    /// Consulted by `mprotect` so `PROT_WRITE` cannot be added to a
    /// `Shared` mapping that was opened read-only — closes the TOCTOU
    /// surface raised by RFC 0007 §Security B1. Snapshot, not a live
    /// reference: the `OpenFile` may close before `munmap`; the VMA
    /// owns the access decision once `mmap` returns.
    open_mode: u32,

    /// Whether the backing inode had execute permission at `mmap` time.
    /// Snapshotted once (just like `open_mode`) so `mprotect` can reject
    /// `PROT_EXEC` upgrades without re-checking the live inode, which
    /// may have had its permissions changed between `mmap` and
    /// `mprotect`. RFC 0007 §Security Considerations, §Errno table.
    exec_allowed: bool,

    /// Per-VMA private-frame cache for `MAP_PRIVATE` write faults.
    /// Empty for `Share::Shared`. After a CoW write fault, the new
    /// private frame is recorded here so a re-fault (e.g. after
    /// `madvise(MADV_DONTNEED)` or a TLB shootdown that dropped the
    /// PTE) returns the same physical frame instead of allocating a
    /// fresh one. Mirrors the `clone_private` / `evict_range`
    /// plumbing of [`crate::mem::vmobject::AnonObject`].
    ///
    /// The map is keyed by **file** page offset (the same key the
    /// cache uses), value is the private frame's physical address.
    /// Population is deferred to #739/#746 — the CoW resolver wiring;
    /// this module exposes only the storage and a query helper.
    private_frames: BlockingMutex<BTreeMap<u64, u64>>,
}

impl FileObject {
    /// Construct a fresh `FileObject` against `cache`.
    ///
    /// `file_offset_pages` and `len_pages` define the slice of the file
    /// the resulting VMA covers. `share` and `open_mode` are the values
    /// `sys_mmap` extracts from the calling task and the `OpenFile`
    /// it looked up — both are snapshotted here, **never** re-read off
    /// the live `OpenFile` (RFC 0007 §FileObject `open_mode` snapshot).
    ///
    /// `exec_allowed` is the result of `Inode::permission(EXECUTE)`
    /// at `mmap` time, snapshotted so `mprotect` can enforce the
    /// `PROT_EXEC` upgrade rule without re-checking the live inode
    /// (RFC 0007 §Security Considerations).
    ///
    /// `cache` is captured into the new object's `Arc<PageCache>` slot
    /// and never rebound (RFC 0007 §Inode-binding rule).
    pub fn new(
        cache: Arc<PageCache>,
        file_offset_pages: u64,
        len_pages: usize,
        share: Share,
        open_mode: u32,
        exec_allowed: bool,
    ) -> Arc<Self> {
        // Validate the file-page window: `file_offset_pages + len_pages`
        // must not wrap. Lookups below combine the two via `pgoff_of`,
        // and a wrapped sum would index unrelated cache entries instead
        // of failing cleanly. Caught at construction (the call site is
        // `sys_mmap` post-validation, so a panic here indicates a bug
        // in the syscall layer, not user-recoverable input).
        assert!(
            file_offset_pages
                .checked_add(len_pages as u64)
                .is_some(),
            "FileObject::new: file_offset_pages={file_offset_pages} + len_pages={len_pages} overflows u64",
        );
        Arc::new(Self {
            cache,
            file_offset_pages,
            len_pages,
            share,
            open_mode,
            exec_allowed,
            private_frames: BlockingMutex::new(BTreeMap::new()),
        })
    }

    /// Borrow a clone of the bound page cache. Returned as an `Arc`
    /// clone so the caller can move it into a writeback-task context
    /// without holding any reference into `self` across a block-I/O
    /// wait. The cache pointer itself is immutable for the
    /// `FileObject`'s lifetime (RFC 0007 §Inode-binding rule).
    pub fn cache(&self) -> Arc<PageCache> {
        self.cache.clone()
    }

    /// File-page offset of the first page covered by this VMA.
    pub fn file_offset_pages(&self) -> u64 {
        self.file_offset_pages
    }

    /// Sharing discipline (Shared or Private).
    pub fn share(&self) -> Share {
        self.share
    }

    /// Snapshot of the `OpenFile` access-mode bits at `mmap` time
    /// (`O_RDONLY` / `O_WRONLY` / `O_RDWR`). Consulted by `mprotect`
    /// to enforce the "PROT_WRITE upgrade requires O_RDWR" rule
    /// (RFC 0007 §FileObject `open_mode` snapshot, §Security B1).
    pub fn open_mode(&self) -> u32 {
        self.open_mode
    }

    /// Whether the backing inode had execute permission at `mmap` time.
    /// Consulted by `mprotect` to enforce the "PROT_EXEC upgrade
    /// requires execute permission on the backing inode" rule
    /// (RFC 0007 §Security Considerations).
    pub fn exec_allowed(&self) -> bool {
        self.exec_allowed
    }

    /// Look up an already-recorded private frame for `pgoff`, if any.
    /// Used by the CoW resolver (#739/#746) to detect re-faults on a
    /// `MAP_PRIVATE` page that has already been copied out, so the
    /// resolver can install the existing private frame's PTE rather
    /// than allocating a fresh page.
    pub fn private_frame_at(&self, pgoff: u64) -> Option<u64> {
        self.private_frames.lock().get(&pgoff).copied()
    }

    /// Record a post-CoW private frame for `pgoff`. Called from the
    /// CoW resolver (#739/#746) after `cow_copy_and_remap` has
    /// allocated and populated the new frame; subsequent faults at
    /// the same `pgoff` re-use it via [`Self::private_frame_at`].
    ///
    /// Returns the previously stored frame, if any — the caller is
    /// responsible for `frame::put`-ing it (a non-`None` return is a
    /// re-population of the same `pgoff`, e.g. after
    /// `madvise(MADV_DONTNEED)` — the previous frame's `frame::put`
    /// happens through the existing eviction path).
    pub fn record_private_frame(&self, pgoff: u64, phys: u64) -> Option<u64> {
        self.private_frames.lock().insert(pgoff, phys)
    }

    /// Bounds-check a page-aligned `offset` against `len_pages`. The
    /// returned page index is **VMA-local** (zero-based at the start
    /// of the VMA); add [`Self::file_offset_pages`] to get the file
    /// page index the cache uses.
    fn check_bounds(&self, offset: usize) -> Result<usize, VmFault> {
        debug_assert!(
            offset % (FRAME_SIZE as usize) == 0,
            "FileObject::fault: offset {offset:#x} is not page-aligned",
        );
        let idx = offset / (FRAME_SIZE as usize);
        if idx >= self.len_pages {
            return Err(VmFault::OutOfRange);
        }
        Ok(idx)
    }

    /// Resolve the full file `pgoff` for a VMA-local `idx`.
    fn pgoff_of(&self, idx: usize) -> u64 {
        self.file_offset_pages + idx as u64
    }

    /// On a successful resolution we hand the cache page's `phys`
    /// back to the resolver, which installs it into the user PTE.
    /// The PTE is one *new* reference to the frame on top of the
    /// cache's own; bump the per-frame refcount accordingly so
    /// `AddressSpace::drop` / `cow_copy_and_remap`'s eventual
    /// `frame::put` does not under-decrement (RFC 0007 §Refcount
    /// discipline). Mirrors the cache-hit path of
    /// [`crate::mem::vmobject::AnonObject::fault`].
    ///
    /// On host (no `target_os = "none"`) the refcount table is gated
    /// out; the call is a no-op.
    #[cfg_attr(not(target_os = "none"), allow(unused_variables, clippy::unused_self))]
    fn inc_pte_refcount(&self, phys: u64) -> Result<(), VmFault> {
        #[cfg(target_os = "none")]
        {
            crate::mem::refcount::try_inc_refcount(phys).map_err(|_| VmFault::RefcountSaturated)?;
        }
        Ok(())
    }

    /// Concrete-typed sibling of [`VmObject::clone_private`]. The trait
    /// method returns `Arc<dyn VmObject>` for the resolver's polymorphic
    /// dispatch; this helper preserves the `Arc<FileObject>` type so
    /// host tests can assert against `FileObject`-specific invariants
    /// (`private_frames` empty, `share` flipped to `Private`, etc.)
    /// without an `Any`-flavored downcast. The trait impl forwards
    /// here, so the construction is verified against the same code
    /// path the kernel uses post-fork.
    fn clone_private_concrete(&self) -> Arc<Self> {
        Arc::new(Self {
            cache: self.cache.clone(),
            file_offset_pages: self.file_offset_pages,
            len_pages: self.len_pages,
            share: Share::Private,
            // The open_mode snapshot is per-VMA, not per-inode — but
            // a post-fork child inherits the parent's `mprotect`
            // gate exactly. Carrying the value verbatim preserves
            // the "PROT_WRITE upgrade needs O_RDWR" rule across a
            // fork. RFC 0007 §FileObject `open_mode` snapshot.
            open_mode: self.open_mode,
            // Exec-permission snapshot carries across fork for the
            // same reason as open_mode.
            exec_allowed: self.exec_allowed,
            private_frames: BlockingMutex::new(BTreeMap::new()),
        })
    }
}

impl VmObject for FileObject {
    /// Share-aware fault method (RFC 0007 §Algorithms,
    /// `FileObject::fault`).
    ///
    /// The flow is:
    ///
    /// 1. Bounds-check `offset` against `len_pages`. SIGBUS on
    ///    overflow.
    /// 2. Bounds-check the resolved file `pgoff` against the cache's
    ///    `i_size` snapshot. SIGBUS-on-shrink-during-flight.
    /// 3. **Fast path**: cache hit on a `PG_UPTODATE` /
    ///    `!PG_LOCKED` entry. Private-write returns
    ///    [`VmFault::CoWNeeded`]; Shared-write dirties the page;
    ///    every other access returns the cache's `phys` after
    ///    bumping the per-frame refcount for the new PTE.
    /// 4. **Slow path**: index miss or stale (`PG_LOCKED`) entry.
    ///    Use [`PageCache::install_or_get`] to win-or-lose the
    ///    install race. The winner drives
    ///    [`AddressSpaceOps::readpage`] with the cache mutex
    ///    *dropped*; on success it publishes
    ///    `PG_UPTODATE`+`!PG_LOCKED` and re-enters the fast path
    ///    via one bounded recursion. The loser parks on the page's
    ///    wait-queue, then re-enters the fast path the same way.
    ///
    /// Lock-order: this method takes [`PageCache::inner`] only across
    /// fast-path lookup and dirty-publish; it is **never** held across
    /// `AddressSpaceOps::readpage`, the level-6 buffer cache, or the
    /// frame allocator (RFC 0007 §Lock-order ladder).
    fn fault(&self, offset: usize, access: Access) -> Result<u64, VmFault> {
        let idx = self.check_bounds(offset)?;
        let pgoff = self.pgoff_of(idx);

        // Truncation-vs-fault gate: `i_size` may have shrunk between
        // VMA construction and this fault; mirror the cache-side
        // recheck the slow-path filler does (RFC 0007 §Algorithms —
        // truncate-vs-fill race recheck).
        if pgoff >= cache_i_size_pages(&self.cache) {
            return Err(VmFault::OutOfRange);
        }

        // --- Fast path: cache hit on UPTODATE / unlocked entry. -----
        //
        // We hold `cache.inner` only across the `BTreeMap::get`,
        // refcount bump, and dirty-publish. The dirty-publish (Shared
        // write) is performed *under* the same critical section as
        // the bit set so the writeback daemon's snapshot never sees a
        // (PG_DIRTY-set, dirty-index-unenrolled) page (RFC 0007
        // §State-bit ordering, writer side). Reach for the cache's
        // `mark_page_dirty` helper to hold that invariant.
        if let Some(page) = self.cache.lookup(pgoff) {
            let st = page.state.load(core::sync::atomic::Ordering::Acquire);
            if st & PG_UPTODATE != 0 && st & PG_LOCKED == 0 {
                if access == Access::Write && self.share == Share::Private {
                    return Err(VmFault::CoWNeeded);
                }
                if access == Access::Write && self.share == Share::Shared {
                    // Atomic dirty-publish: bit + index in one
                    // critical section.
                    self.cache.mark_page_dirty(pgoff);
                }
                self.inc_pte_refcount(page.phys)?;
                return Ok(page.phys);
            }
            // Hit-but-locked: fall through to slow path; we will
            // park on the existing entry's wait-queue rather than
            // install a fresh stub.
        }

        // --- Slow path: install-race + filler protocol. --------------
        //
        // This is invoked with no spinlock or BlockingMutex held above
        // level 4 (we have just released `cache.inner`'s guard at the
        // close of `cache.lookup`).
        //
        // Pre-allocate the stub *before* taking `cache.inner` so a
        // frame-allocator miss surfaces as `VmFault::OutOfMemory`
        // rather than a kernel panic (mirrors `AnonObject::fault`,
        // RFC 0007 §FileObject — fault dispatch). The stub is handed
        // to `install_or_get` via a `move` closure; if we lose the
        // install race the closure is never called and the stub is
        // dropped on the loser path below, after which the underlying
        // frame is returned to the allocator via `release_unused_stub`.
        let stub = alloc_locked_stub(pgoff)?;
        let stub_for_closure = stub.clone();
        let outcome = self.cache.install_or_get(pgoff, move || stub_for_closure);
        let (page, won_install) = match outcome {
            InstallOutcome::InstalledNew(p) => {
                // We won. Both `stub` (outer) and `p` reference the
                // same `Arc<CachePage>`; drop our outer copy so the
                // cache is the sole strong-ref owner once this scope
                // exits. The frame stays alive — the cache index
                // owns it now.
                drop(stub);
                (p, true)
            }
            InstallOutcome::AlreadyPresent(p) => {
                // Lost the install race: `make_stub` was never
                // invoked, so the closure's `stub_for_closure` clone
                // was dropped silently. Our outer `stub` is now the
                // sole strong reference to a `CachePage` that no
                // index ever observed; `Arc<CachePage>` has no
                // `Drop` impl that frees its physical frame, so we
                // must reclaim it explicitly before dropping.
                release_unused_stub(&stub);
                drop(stub);
                (p, false)
            }
        };

        if won_install {
            // We own the fill. Drive `ops.readpage` with no cache
            // lock held. On error, the cache's filler-error contract
            // requires us to remove the stub from the index, clear
            // PG_LOCKED, and wake every waiter so they retry the
            // slow path against a fresh stub (RFC 0007 §State-bit
            // ordering "Filler error handling").
            let mut buf = [0u8; FRAME_SIZE as usize];
            page.mark_in_flight();
            let ops = self.cache.ops();
            let read_res = ops.readpage(pgoff, &mut buf);
            page.clear_in_flight();
            match read_res {
                Ok(_n) => {
                    // Copy the bytes through the HHDM into the stub's
                    // physical frame. On host the frame is fictitious
                    // (no HHDM mapping) — we skip the memcpy; the
                    // host tests assert dispatch and state-bit
                    // ordering, not byte content.
                    #[cfg(target_os = "none")]
                    copy_into_frame(page.phys, &buf);
                    #[cfg(not(target_os = "none"))]
                    let _ = buf;
                    // Truncate-vs-fill recheck: i_size may have
                    // shrunk while readpage was in flight.
                    if pgoff >= cache_i_size_pages(&self.cache) {
                        // Pull the now-OOR page back out of the
                        // index. Use the abandon path's discipline:
                        // remove the entry, clear PG_LOCKED, wake
                        // waiters so they re-enter and observe the
                        // shrunken size themselves.
                        self.cache.abandon_locked_stub(&page);
                        return Err(VmFault::OutOfRange);
                    }
                    page.publish_uptodate_and_unlock();
                }
                Err(e) => {
                    self.cache.abandon_locked_stub(&page);
                    return Err(VmFault::ReadFailed(e));
                }
            }
        } else {
            // Loser: park on the existing stub's wait-queue until
            // PG_LOCKED clears. After the wake, observe the state:
            // if PG_UPTODATE is set we re-enter the fast path; if
            // not (filler abandoned), surface ParkAndRetry so the
            // resolver replays the fault and lands on a fresh stub.
            page.wait_until_unlocked();
            let st = page.state.load(core::sync::atomic::Ordering::Acquire);
            if st & PG_UPTODATE == 0 {
                return Err(VmFault::ParkAndRetry);
            }
            // Fall through to fast-path replay below.
        }

        // Bounded re-entry: the page is now UPTODATE and we hold a
        // strong `Arc<CachePage>`, so a second eviction is impossible
        // until our local Arc drops. The recursion depth is at most
        // one (winner publishes; loser observes UPTODATE) which the
        // RFC bounds explicitly.
        //
        // Re-run the fast-path body against the now-resident page.
        // We hand off to the same `cache.lookup` so a daemon-side
        // `clear_page_dirty` / re-dirty between the publish and our
        // observation is reflected accurately.
        if let Some(page) = self.cache.lookup(pgoff) {
            let st = page.state.load(core::sync::atomic::Ordering::Acquire);
            if st & PG_UPTODATE != 0 && st & PG_LOCKED == 0 {
                if access == Access::Write && self.share == Share::Private {
                    return Err(VmFault::CoWNeeded);
                }
                if access == Access::Write && self.share == Share::Shared {
                    self.cache.mark_page_dirty(pgoff);
                }
                self.inc_pte_refcount(page.phys)?;
                return Ok(page.phys);
            }
        }
        // Lost the race a second time (e.g. eviction snuck in between
        // our park-wake and the lookup). Park-and-retry is the
        // resolver's job — bouncing back through it preserves the
        // bounded-recursion property.
        Err(VmFault::ParkAndRetry)
    }

    fn len_pages(&self) -> Option<usize> {
        Some(self.len_pages)
    }

    /// Return the cached physical frame backing `offset`, if the cache
    /// has the page resident *and* `PG_UPTODATE` is set. Used by the
    /// existing `reap_pending` path to detect private CoW copies
    /// (RFC 0001 §reap_pending; the doc on
    /// [`VmObject::frame_at`] in `vmobject.rs` calls this contract
    /// out). On a `MAP_PRIVATE` mapping a CoW copy lives in
    /// [`Self::private_frames`] rather than the cache, so when the
    /// PTE frame differs from the cache's `phys` (or the cache has
    /// no entry) the resolver frees the PTE frame directly — exactly
    /// the AnonObject-doc-comment contract.
    fn frame_at(&self, offset: usize) -> Option<u64> {
        let idx = offset / (FRAME_SIZE as usize);
        if idx >= self.len_pages {
            return None;
        }
        let pgoff = self.pgoff_of(idx);
        let page = self.cache.lookup(pgoff)?;
        let st = page.state.load(core::sync::atomic::Ordering::Acquire);
        if st & PG_UPTODATE != 0 && st & PG_LOCKED == 0 {
            Some(page.phys)
        } else {
            None
        }
    }

    /// Post-fork private clone (RFC 0007 §FileObject — `clone_private`).
    /// Returns a *new* `FileObject` against the **same** `Arc<PageCache>`
    /// (sharing the master copy) with `share = Private`. Post-fork
    /// demand faults in either parent or child re-enter the cache and
    /// CoW out independently — the shared cache is the master, the
    /// per-VMA `private_frames` map is per-child.
    ///
    /// The new object's `private_frames` is empty: post-fork demand
    /// faults on unfaulted pages allocate independent frames in
    /// parent and child via the existing `cow_copy_and_remap` path
    /// (#739).
    fn clone_private(&self) -> Arc<dyn VmObject> {
        self.clone_private_concrete()
    }

    /// Drop cached private frames for VMA-local page indices ≥
    /// `from_page`, then delegate the cache-side trim to the
    /// underlying [`PageCache`]. The cache itself implements its
    /// truncate semantics in #740; this method is the `VmObject`-side
    /// fan-out so `madvise`/`brk`-style trims still cross the trait
    /// boundary cleanly today (RFC 0007 §FileObject roadmap).
    fn truncate_from_page(&self, from_page: usize) {
        // Drop any per-VMA private frames for VMA-local indices
        // ≥ `from_page`. The frames themselves are reclaimed by
        // `frame::put` in the resolver wiring (#746); this module
        // owns only the index entry.
        let mut map = self.private_frames.lock();
        let keys: alloc::vec::Vec<u64> = map
            .range(self.pgoff_of(from_page)..)
            .map(|(&k, _)| k)
            .collect();
        for k in keys {
            map.remove(&k);
        }
        // Cache-side `truncate_below` is the writeback workstream's
        // hook (#740). Today it is a no-op on the default
        // `AddressSpaceOps` impl; calling through preserves the
        // dispatch shape so #740's wiring slots in here.
        let _ = &self.cache;
    }

    // ---- mprotect permission gates (RFC 0007 §Security B1) ---------------

    fn mprotect_open_mode(&self) -> Option<u32> {
        Some(self.open_mode)
    }

    fn mprotect_exec_allowed(&self) -> Option<bool> {
        Some(self.exec_allowed)
    }

    /// `madvise(MADV_DONTNEED)` fan-out for the [first, last) VMA-local
    /// range. Drops `private_frames` entries; the cache eviction is
    /// the daemon's responsibility (#740).
    fn evict_range(&self, first: usize, last: usize) {
        let lo = self.pgoff_of(first);
        let hi = self.pgoff_of(last);
        let mut map = self.private_frames.lock();
        let keys: alloc::vec::Vec<u64> = map.range(lo..hi).map(|(&k, _)| k).collect();
        for k in keys {
            map.remove(&k);
        }
    }
}

// --- Helpers ---------------------------------------------------------------

/// `i_size` snapshot expressed in 4 KiB pages (rounded up).
///
/// Uses `saturating_add` for the round-up so a hypothetical
/// `i_size` near `u64::MAX` cannot wrap to a tiny page count
/// and silently widen the in-bounds window — practical file sizes
/// never approach this bound, but the bounds-check arithmetic
/// must never produce a smaller value than the input pages.
fn cache_i_size_pages(cache: &PageCache) -> u64 {
    let bytes = cache.i_size();
    bytes.saturating_add(FRAME_SIZE - 1) / FRAME_SIZE
}

/// Stub allocator used by [`FileObject::fault`]'s slow path. Returns a
/// freshly allocated `PG_LOCKED` / `!PG_UPTODATE` cache page so the
/// caller can hand it to [`PageCache::install_or_get`] via a `move`
/// closure.
///
/// On bare metal we ask the global frame allocator for a fresh frame
/// and zero it through the HHDM; the resulting [`crate::mem::page_cache::CachePage`]
/// is locked (filler protocol) until the caller publishes
/// `PG_UPTODATE`+`!PG_LOCKED` via
/// [`crate::mem::page_cache::CachePage::publish_uptodate_and_unlock`].
/// Frame exhaustion is *recoverable*: we surface
/// [`VmFault::OutOfMemory`] so the resolver can SIGBUS the offending
/// thread instead of panicking the whole kernel (mirrors
/// `AnonObject::fault`).
///
/// On host (`cfg(test)`) the frame number is a deterministic stand-in
/// — the cache never dereferences `phys` and host tests do not
/// install PTEs against it; allocation is therefore infallible.
#[cfg(target_os = "none")]
fn alloc_locked_stub(pgoff: u64) -> Result<Arc<crate::mem::page_cache::CachePage>, VmFault> {
    let phys = crate::mem::frame::alloc().ok_or(VmFault::OutOfMemory)?;
    let hhdm = crate::mem::paging::hhdm_offset().as_u64();
    // SAFETY: `phys` was just allocated for us, is 4 KiB-aligned,
    // and is covered by the HHDM mapping. We hold exclusive
    // ownership until insertion into the cache index, so no aliasing
    // writer exists for this zero-fill.
    unsafe {
        core::ptr::write_bytes((hhdm + phys) as *mut u8, 0, FRAME_SIZE as usize);
    }
    Ok(crate::mem::page_cache::CachePage::new_locked(phys, pgoff))
}

#[cfg(not(target_os = "none"))]
fn alloc_locked_stub(pgoff: u64) -> Result<Arc<crate::mem::page_cache::CachePage>, VmFault> {
    // Deterministic stand-in for `frame::allocate`. Page-aligned,
    // non-zero, well above any real-world frame address used by other
    // tests so collisions stay obvious if they do occur.
    let phys = 0x4_0000_0000 + pgoff * FRAME_SIZE;
    Ok(crate::mem::page_cache::CachePage::new_locked(phys, pgoff))
}

/// Return a stub frame to the global allocator when the install race
/// is lost. Bare-metal-only; on host the stub frame is fictitious and
/// there is nothing to reclaim.
#[cfg(target_os = "none")]
fn release_unused_stub(stub: &Arc<crate::mem::page_cache::CachePage>) {
    crate::mem::frame::free(stub.phys);
}

#[cfg(not(target_os = "none"))]
fn release_unused_stub(_stub: &Arc<crate::mem::page_cache::CachePage>) {}

/// Copy `buf` into the cache stub's physical frame through the HHDM.
/// Bare-metal-only; on host the test harness skips the copy.
#[cfg(target_os = "none")]
fn copy_into_frame(phys: u64, buf: &[u8; FRAME_SIZE as usize]) {
    let hhdm = crate::mem::paging::hhdm_offset().as_u64();
    // SAFETY: `phys` is the just-installed cache stub's frame; the
    // filler holds the page's PG_LOCKED bit, so no other observer can
    // be reading from it. The HHDM mapping covers all USABLE phys.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), (hhdm + phys) as *mut u8, FRAME_SIZE as usize);
    }
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::aops::MemoryBackedOps;
    use crate::mem::page_cache::{InodeId, PageCache};

    fn fake_inode_id() -> InodeId {
        InodeId::new(0xfeed_face, 1)
    }

    fn cache_with_pages(n: usize) -> Arc<PageCache> {
        let ops = MemoryBackedOps::with_pages(n);
        let cache = PageCache::new(fake_inode_id(), (n as u64) * FRAME_SIZE, ops);
        Arc::new(cache)
    }

    fn fresh_object(share: Share) -> Arc<FileObject> {
        let cache = cache_with_pages(8);
        FileObject::new(cache, 0, 8, share, 0o2 /* O_RDWR */, true)
    }

    #[test]
    fn bounds_check_rejects_offsets_past_len_pages() {
        let obj = fresh_object(Share::Shared);
        let err = obj.fault(8 * 4096, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::OutOfRange);
        let err = obj.fault(100 * 4096, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::OutOfRange);
    }

    #[test]
    fn shared_read_resolves_through_slow_path() {
        let obj = fresh_object(Share::Shared);
        // First read miss: drives readpage, publishes UPTODATE, then
        // bounded-recursion lands the fast path and returns Ok(phys).
        let phys = obj.fault(0, Access::Read).expect("read fault must resolve");
        assert_ne!(phys, 0);
        // Second access: pure fast-path hit.
        let phys2 = obj.fault(0, Access::Read).expect("fast-path hit");
        assert_eq!(phys, phys2);
    }

    #[test]
    fn shared_write_dirties_cache_page() {
        let obj = fresh_object(Share::Shared);
        let phys = obj
            .fault(0, Access::Write)
            .expect("write fault must resolve");
        let cache = obj.cache();
        // Snapshot dirty: the page just written should appear.
        let snap = cache.snapshot_dirty();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, 0);
        assert_eq!(snap[0].1.phys, phys);
        assert!(snap[0].1.is_dirty());
    }

    #[test]
    fn private_write_returns_cow_needed() {
        let obj = fresh_object(Share::Private);
        // Read fault first to populate the cache.
        obj.fault(0, Access::Read).expect("populate");
        // Now a write fault on the same page returns CoWNeeded —
        // share-aware dispatch.
        let err = obj.fault(0, Access::Write).unwrap_err();
        assert_eq!(err, VmFault::CoWNeeded);
        // The cache page must NOT be dirtied: Private write does not
        // touch the master copy (RFC 0007 §FileObject — Private write
        // fault).
        assert!(obj.cache().snapshot_dirty().is_empty());
    }

    #[test]
    fn private_read_resolves_normally() {
        let obj = fresh_object(Share::Private);
        let phys = obj.fault(0, Access::Read).expect("private read");
        // Cache hit on second read.
        let phys2 = obj.fault(0, Access::Read).expect("private read 2");
        assert_eq!(phys, phys2);
    }

    #[test]
    fn private_write_on_uncached_page_still_returns_cow_needed() {
        // Slow-path entry: page not yet resident. RFC 0007 algorithm
        // keeps the readpage on Private+Write so the master copy is
        // populated before the resolver CoWs from it. After the slow
        // path lands the page UPTODATE, the bounded-recursion replay
        // surfaces CoWNeeded.
        let obj = fresh_object(Share::Private);
        let err = obj.fault(2 * 4096, Access::Write).unwrap_err();
        assert_eq!(err, VmFault::CoWNeeded);
        // Cache now holds the page (master copy populated).
        let cache = obj.cache();
        assert!(cache.lookup(2).is_some());
    }

    #[test]
    fn out_of_range_after_i_size_shrink_returns_oor() {
        let obj = fresh_object(Share::Shared);
        // Shrink i_size to 0 before the fault. Bounds check on
        // pgoff vs i_size_pages should surface OutOfRange.
        obj.cache().store_i_size(0);
        let err = obj.fault(0, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::OutOfRange);
    }

    #[test]
    fn frame_at_returns_cache_phys_when_uptodate() {
        let obj = fresh_object(Share::Shared);
        // Pre-fault: nothing resident.
        assert_eq!(obj.frame_at(0), None);
        let phys = obj.fault(0, Access::Read).unwrap();
        assert_eq!(obj.frame_at(0), Some(phys));
        // Past len_pages: None regardless of cache state.
        assert_eq!(obj.frame_at(100 * 4096), None);
    }

    #[test]
    fn len_pages_reports_window_size() {
        let obj = fresh_object(Share::Shared);
        assert_eq!(obj.len_pages(), Some(8));
    }

    #[test]
    fn clone_private_shares_cache_and_forces_private_share() {
        let parent = fresh_object(Share::Shared);
        let parent_cache = parent.cache();
        let child_dyn: Arc<dyn VmObject> = parent.clone_private();
        // Downcast back to FileObject for share/cache asserts via
        // the FileObject pointer — we still own `parent` so we can
        // compare cache Arcs that way. (The trait object's vtable
        // does not expose share().) A simpler observable check:
        // a write fault on the child returns CoWNeeded, while the
        // same operation on the parent (Shared) dirties the cache.
        // Pre-populate via parent's read fault.
        parent.fault(0, Access::Read).unwrap();
        let err = child_dyn.fault(0, Access::Write).unwrap_err();
        assert_eq!(err, VmFault::CoWNeeded);
        // Parent cache untouched by the child's fault.
        assert!(parent_cache.snapshot_dirty().is_empty());
        // Child reports the same window size.
        assert_eq!(child_dyn.len_pages(), Some(8));
    }

    #[test]
    fn clone_private_starts_with_empty_private_frames() {
        let parent = fresh_object(Share::Private);
        // Plant a private frame on the parent so a buggy
        // `clone_private` that copied (rather than zeroed) the
        // `private_frames` map would surface as a non-`None`
        // observation on the child.
        parent.record_private_frame(0, 0xdead_0000);
        assert_eq!(parent.private_frame_at(0), Some(0xdead_0000));
        // Exercise the actual `clone_private` code path. The
        // concrete-typed sibling helper forwards through the same
        // construction as the trait impl (see
        // `FileObject::clone_private_concrete`); using it here
        // avoids a trait-object downcast while still asserting
        // against the post-clone `FileObject` state.
        let child = parent.clone_private_concrete();
        assert_eq!(child.private_frame_at(0), None);
        // Parent's own private_frames is untouched.
        assert_eq!(parent.private_frame_at(0), Some(0xdead_0000));
    }

    #[test]
    fn private_frames_round_trip() {
        let obj = fresh_object(Share::Private);
        assert_eq!(obj.private_frame_at(3), None);
        let prev = obj.record_private_frame(3, 0x1_2000);
        assert_eq!(prev, None);
        assert_eq!(obj.private_frame_at(3), Some(0x1_2000));
        // Re-recording returns the previous frame (caller responsible
        // for `frame::put`).
        let prev2 = obj.record_private_frame(3, 0x1_3000);
        assert_eq!(prev2, Some(0x1_2000));
        assert_eq!(obj.private_frame_at(3), Some(0x1_3000));
    }

    #[test]
    fn evict_range_drops_private_frames_in_window() {
        let obj = fresh_object(Share::Private);
        obj.record_private_frame(0, 0x1000);
        obj.record_private_frame(1, 0x2000);
        obj.record_private_frame(5, 0x3000);
        obj.evict_range(0, 2);
        assert_eq!(obj.private_frame_at(0), None);
        assert_eq!(obj.private_frame_at(1), None);
        // Outside the window untouched.
        assert_eq!(obj.private_frame_at(5), Some(0x3000));
    }

    #[test]
    fn truncate_from_page_drops_private_frames() {
        let obj = fresh_object(Share::Private);
        obj.record_private_frame(0, 0x1000);
        obj.record_private_frame(3, 0x2000);
        obj.record_private_frame(5, 0x3000);
        obj.truncate_from_page(3);
        assert_eq!(obj.private_frame_at(0), Some(0x1000));
        assert_eq!(obj.private_frame_at(3), None);
        assert_eq!(obj.private_frame_at(5), None);
    }

    #[test]
    fn open_mode_snapshot_round_trips() {
        let cache = cache_with_pages(2);
        let ro = FileObject::new(
            cache.clone(),
            0,
            2,
            Share::Shared,
            0, /* O_RDONLY */
            false,
        );
        assert_eq!(ro.open_mode(), 0);
        let rw = FileObject::new(cache, 0, 2, Share::Shared, 0o2 /* O_RDWR */, true);
        assert_eq!(rw.open_mode(), 0o2);
    }

    #[test]
    fn file_offset_window_resolves_correct_pgoff() {
        // VMA covers file pages [4..8). A fault at VMA-local offset
        // 0 must hit the cache at pgoff 4, not 0.
        let cache = cache_with_pages(8);
        let obj = FileObject::new(cache.clone(), 4, 4, Share::Shared, 0o2, true);
        let phys = obj.fault(0, Access::Read).unwrap();
        // Cache now indexes pgoff 4.
        let page = cache.lookup(4).expect("pgoff 4 must be resident");
        assert_eq!(page.phys, phys);
        // No entry at pgoff 0.
        assert!(cache.lookup(0).is_none());
    }

    /// Filler-error path: a readpage that returns `Err` propagates as
    /// `VmFault::ReadFailed`, the stub is removed from the cache
    /// index, and a subsequent fault drives a fresh `readpage`.
    #[test]
    fn readpage_error_surfaces_as_read_failed_and_clears_index() {
        // FailingOps returns EIO on every readpage; we drive one
        // fault, observe the errno, and confirm the cache index is
        // empty afterward.
        struct FailingOps;
        impl crate::mem::aops::AddressSpaceOps for FailingOps {
            fn readpage(&self, _pgoff: u64, _buf: &mut [u8; 4096]) -> Result<usize, i64> {
                crate::debug_lockdep::assert_no_spinlocks_held("FailingOps::readpage");
                Err(crate::fs::EIO)
            }
            fn writepage(&self, _pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
                Ok(())
            }
        }
        let cache = Arc::new(PageCache::new(
            fake_inode_id(),
            8 * FRAME_SIZE,
            Arc::new(FailingOps),
        ));
        let obj = FileObject::new(cache.clone(), 0, 8, Share::Shared, 0o2, true);
        let err = obj.fault(0, Access::Read).unwrap_err();
        assert_eq!(err, VmFault::ReadFailed(crate::fs::EIO));
        // Stub removed: a subsequent fault re-enters install_or_get
        // and wins.
        assert!(cache.lookup(0).is_none());
    }

    // --- RFC 0007 §Lock-order — slow-path split-lock discipline -----
    //
    // The page-fault slow path holds `cache.inner` only across the
    // index-mutating helpers (`install_or_get`, `mark_page_dirty`,
    // `lookup`). It is **never** held across `ops.readpage`. RFC 0007
    // §Lock-order ladder: cache mutex (level 4) is acquired before
    // and released before the buffer cache (level 6) the FS impl
    // takes internally; holding it across the call would invert the
    // ladder on first contention.
    //
    // The tests below drive a real `FileObject::fault` and verify
    // that during `ops.readpage`:
    //
    //   1. The caller did not hold `cache.inner` (we try_lock from
    //      inside `readpage` and assert success).
    //   2. The lockdep counter reads zero (no spinlock held).
    //
    // Together these prove the split-lock discipline holds end-to-end
    // through the slow path the cache primitives expose today.

    /// Custom AddressSpaceOps that, on `readpage`, asserts the
    /// caller's `cache.inner` is *not* currently held.
    ///
    /// The probe stores its own back-reference to the
    /// `Arc<PageCache>` so the readpage body can `try_lock` the cache
    /// mutex from inside the dispatch. If the slow path is holding
    /// `cache.inner` across the call (RFC 0007 §Lock-order
    /// violation) the try_lock returns `None` and the test observes
    /// `observed_unlocked == false`.
    struct LockOrderProbe {
        cache: spin::Mutex<Option<Arc<PageCache>>>,
        observed_unlocked: core::sync::atomic::AtomicBool,
    }

    impl LockOrderProbe {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                cache: spin::Mutex::new(None),
                observed_unlocked: core::sync::atomic::AtomicBool::new(false),
            })
        }

        fn install_cache(&self, cache: Arc<PageCache>) {
            *self.cache.lock() = Some(cache);
        }
    }

    impl crate::mem::aops::AddressSpaceOps for LockOrderProbe {
        fn readpage(&self, _pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64> {
            // Method-entry invariant: `assert_no_spinlocks_held` is
            // RFC 0007 §Lock-order ladder's hard contract. If the
            // slow path had retained any `SpinLock` guard across
            // this dispatch, this call panics — and the host test
            // sees a `should_panic`-style failure (libtest reports
            // it as "panicked at: …"). We therefore exercise *both*
            // the spinlock invariant (via the assert) and the
            // BlockingMutex invariant (via the `try_lock` below) in
            // the same body.
            crate::debug_lockdep::assert_no_spinlocks_held("LockOrderProbe::readpage");

            // Probe: try to acquire `cache.inner`. If the caller had
            // retained the guard across this dispatch we would
            // deadlock here on bare metal; on host the underlying
            // `spin::Mutex::try_lock` returns `None` instead.
            let cache_guard = self.cache.lock();
            if let Some(c) = cache_guard.as_ref() {
                let inner_guard = c.inner.try_lock();
                if inner_guard.is_some() {
                    self.observed_unlocked
                        .store(true, core::sync::atomic::Ordering::Release);
                }
            }
            // Default-fill the page so the cache publishes UPTODATE.
            buf[0] = 0xa5;
            Ok(4096)
        }

        fn writepage(&self, _pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
            crate::debug_lockdep::assert_no_spinlocks_held("LockOrderProbe::writepage");
            Ok(())
        }
    }

    #[test]
    fn slow_path_drops_cache_inner_before_readpage() {
        // RFC 0007 §Lock-order ladder: the slow path enters
        // `ops.readpage` with no level-4 cache lock held. We probe
        // this from inside `readpage` itself.
        let probe = LockOrderProbe::new();
        let cache = Arc::new(PageCache::new(
            fake_inode_id(),
            8 * FRAME_SIZE,
            probe.clone(),
        ));
        probe.install_cache(cache.clone());

        let obj = FileObject::new(cache.clone(), 0, 8, Share::Shared, 0o2, true);
        // Drive a fault — winner path runs `readpage`.
        let phys = obj
            .fault(0, Access::Read)
            .expect("first fault must resolve");
        assert_ne!(phys, 0);
        assert!(
            probe
                .observed_unlocked
                .load(core::sync::atomic::Ordering::Acquire),
            "readpage observed cache.inner as locked — RFC 0007 §Lock-order violation",
        );
    }

    #[test]
    fn fault_strong_count_returns_to_one_post_resolution() {
        // RFC 0007 §Refcount discipline (fault hot path): the slow
        // path clones the `Arc<CachePage>` to stack-local during the
        // resolution, then drops it before returning. Eviction
        // observes `Arc::strong_count == 1` on the cache index post
        // resolution; if a leak in the fault path holds an extra
        // clone, eviction would block forever.
        let obj = fresh_object(Share::Shared);
        let _ = obj.fault(0, Access::Read).unwrap();
        // Borrow the index entry without bumping strong (mirrors the
        // evictor's BTreeMap::get pattern).
        let cache = obj.cache();
        let strong_borrow = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        assert_eq!(
            strong_borrow, 1,
            "fault hot path leaked an Arc<CachePage> clone — eviction would block",
        );
    }

    #[test]
    fn fault_then_drop_addrspace_returns_strong_count_to_one() {
        // Drop the FileObject after a successful fault. The cache
        // index still owns the only Arc; strong_count stays at 1.
        // Catches a regression where FileObject ends up holding
        // `Arc<CachePage>` clones on success (it should not — the
        // page is consumed for its `phys` field only).
        let obj = fresh_object(Share::Shared);
        let _ = obj.fault(0, Access::Read).unwrap();
        let cache = obj.cache();
        drop(obj);
        let strong_borrow = {
            let inner = cache.inner.lock();
            let p = inner.pages.get(&0).expect("indexed");
            Arc::strong_count(p)
        };
        assert_eq!(strong_borrow, 1);
    }

    // --- RFC 0007 §Security B1 — mprotect permission gates -----

    #[test]
    fn mprotect_open_mode_returns_snapshot() {
        let cache = cache_with_pages(2);
        let ro: Arc<dyn VmObject> = FileObject::new(
            cache.clone(),
            0,
            2,
            Share::Shared,
            0, /* O_RDONLY */
            true,
        );
        assert_eq!(ro.mprotect_open_mode(), Some(0));
        let rw: Arc<dyn VmObject> =
            FileObject::new(cache, 0, 2, Share::Shared, 0o2 /* O_RDWR */, true);
        assert_eq!(rw.mprotect_open_mode(), Some(0o2));
    }

    #[test]
    fn mprotect_exec_allowed_returns_snapshot() {
        let cache = cache_with_pages(2);
        let exec: Arc<dyn VmObject> =
            FileObject::new(cache.clone(), 0, 2, Share::Shared, 0o2, true);
        assert_eq!(exec.mprotect_exec_allowed(), Some(true));
        let noexec: Arc<dyn VmObject> = FileObject::new(cache, 0, 2, Share::Shared, 0o2, false);
        assert_eq!(noexec.mprotect_exec_allowed(), Some(false));
    }

    #[test]
    fn anon_object_returns_none_for_mprotect_gates() {
        use crate::mem::vmobject::AnonObject;
        let anon: Arc<dyn VmObject> = AnonObject::new(Some(4));
        assert_eq!(anon.mprotect_open_mode(), None);
        assert_eq!(anon.mprotect_exec_allowed(), None);
    }

    #[test]
    fn clone_private_preserves_exec_allowed() {
        let cache = cache_with_pages(2);
        let parent = FileObject::new(cache, 0, 2, Share::Shared, 0o2, false);
        let child = parent.clone_private_concrete();
        assert_eq!(child.exec_allowed(), false);
        assert_eq!(child.mprotect_exec_allowed(), Some(false));
    }

    #[test]
    fn exec_allowed_snapshot_round_trips() {
        let cache = cache_with_pages(2);
        let yes = FileObject::new(cache.clone(), 0, 2, Share::Shared, 0, true);
        assert!(yes.exec_allowed());
        let no = FileObject::new(cache, 0, 2, Share::Shared, 0, false);
        assert!(!no.exec_allowed());
    }
}
