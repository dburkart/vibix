//! `AddressSpaceOps` — per-filesystem hook the page cache calls on
//! miss / writeback / readahead / truncate.
//!
//! Implements RFC 0007 §`AddressSpaceOps`. The trait is the seam
//! between the generic per-inode page cache (`mem::page_cache`) and
//! per-filesystem block I/O drivers (e.g. ext2 in
//! `fs/ext2/aops.rs` — wired up in #749/#750/#751/#752, out of
//! scope here).
//!
//! # Method-entry invariant — `assert_no_spinlocks_held`
//!
//! RFC 0007 §Lock-order ladder mandates that **every implementation
//! of every method on this trait** call
//! [`crate::debug_lockdep::assert_no_spinlocks_held`] **at the very
//! first instruction** of the body. This is the same hard runtime
//! invariant RFC 0004 §Buffer cache enforces for `BlockCache::bread`
//! / `sync_dirty_buffer`: holding a spinlock across the block-I/O
//! wait the FS impl is about to issue would deadlock at first
//! contention.
//!
//! Today the underlying counter is `cfg(debug_assertions)`-gated and
//! release builds compile the assert to a no-op (see
//! `kernel/src/debug_lockdep.rs`). RFC 0007 raises the bar to "hard
//! runtime, not debug-only" — the migration of the counter itself to
//! an unconditional atomic is tracked under the deferred follow-up
//! cited at the bottom of this module. The trait contract here
//! therefore specifies the *call*; the eventual lift of
//! `debug_assertions` gating from `debug_lockdep` will turn it into
//! a runtime trip without any change at the trait-impl call sites.
//!
//! The default-method bodies in this module — `readahead` and
//! `truncate_below` — already call the assert.
//!
//! # Page-buffer shape
//!
//! `readpage` / `writepage` deal in fixed `&mut [u8; 4096]` /
//! `&[u8; 4096]` buffers, not `&[u8]` slices. The fixed-array shape:
//!
//!   1. Encodes the page-size invariant in the type system. A
//!      filesystem driver cannot accidentally pass a half-page.
//!   2. Lets the page-cache fault path point the buffer directly at
//!      the HHDM window of the cached frame without a length check
//!      at every call site.
//!
//! # Inode-binding rule
//!
//! The `Arc<dyn AddressSpaceOps>` stored on a `PageCache` is captured
//! at inode construction and **never rebound** for the lifetime of
//! the inode. RFC 0007 §Inode-binding rule forbids replacing the ops
//! pointer in place — a different inode (e.g. surfaced by a second
//! `execve` of the same path that resolved to a different inode
//! number) constructs its own distinct `PageCache` against its own
//! ops. This is a security invariant: a hot-swap of `ops` would let
//! a subsequent `readpage` return data from a *different* on-disk
//! object than the one the calling task opened.
//!
//! # Out of scope (sibling issues)
//!
//! - Any concrete `AddressSpaceOps` impl. ext2's lives in
//!   `fs/ext2/aops.rs` (#749/#750/#751/#752); ramfs/tarfs do not
//!   need a real `readpage` path because their data is already in
//!   memory.
//! - The eviction / writeback daemon plumbing that calls
//!   `writepage` from outside the fault path (#740, #742).
//! - Readahead heuristic / `ra_state` (#741); the default
//!   `readahead` no-op here is the placeholder until #741 wires the
//!   first heuristic.
//! - Migrating `debug_lockdep::assert_no_spinlocks_held` from
//!   `cfg(debug_assertions)`-gated to unconditional-runtime (deferred
//!   follow-up — see RFC 0007 §Lock-order ladder; tracked separately
//!   so it doesn't gate this trait landing).

use crate::debug_lockdep::assert_no_spinlocks_held;

/// Per-filesystem hook the page cache calls on miss / writeback /
/// readahead / truncate.
///
/// `Send + Sync` so an `Arc<dyn AddressSpaceOps>` can be shared
/// between the per-inode page cache, the writeback daemon, and any
/// fault-path observer without further locking.
///
/// # Invariants
///
/// - **No spinlock held on entry.** Every method body must call
///   [`crate::debug_lockdep::assert_no_spinlocks_held`] as its first
///   action (RFC 0007 §Lock-order ladder). The default-method bodies
///   here do; required-method impls must do the same.
/// - **No `PageCache::inner` lock held on entry.** Callers (the
///   page-cache slow-path) drop the level-4 cache mutex before
///   invoking any method on this trait. Implementations may take
///   their own level-6 (buffer cache) and below locks freely.
/// - **Inode-bound.** A given trait object is captured at
///   `PageCache` construction and never rebound. Implementations
///   that need to consult per-inode metadata may snapshot it during
///   their own construction and store it inline; the page cache
///   will not pass an `inode_id` at every call.
pub trait AddressSpaceOps: Send + Sync {
    /// Populate `buf` with the on-disk contents of file page
    /// `pgoff`. May block on block I/O. Returns the number of bytes
    /// actually filled in `buf`; the caller (the page-cache
    /// install-then-uptodate path) zero-fills the tail
    /// `[bytes_filled .. 4096)` if the FS reports a short read past
    /// `i_size`.
    ///
    /// On success the byte count is in `0..=4096`. Pages entirely
    /// past EOF return `Ok(0)` and `buf` is left untouched (the
    /// caller pre-zeroes).
    ///
    /// On error the impl returns a faithful errno (negative i64 in
    /// vibix's errno convention; see `kernel/src/syscall/errno.rs`).
    /// The page-cache filler-error path
    /// (`PageCache::abandon_locked_stub`) propagates this errno to
    /// the faulting task.
    ///
    /// **Implementation requirement:** call
    /// `assert_no_spinlocks_held("…readpage")` as the first line of
    /// the body. RFC 0007 §Lock-order ladder.
    fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64>;

    /// Write `buf` back to file page `pgoff`. May block on block
    /// I/O. Synchronous from the caller's perspective: the impl
    /// must drive the buffer-cache `mark_dirty` + `sync_dirty_buffer`
    /// chain to completion before returning `Ok`.
    ///
    /// On error returns a faithful errno. The page-cache writeback
    /// daemon turns the error into a `wb_err` bump (errseq pattern,
    /// surfaced through `fsync` — see RFC 0007 §`PageCache`).
    ///
    /// **Implementation requirement:** call
    /// `assert_no_spinlocks_held("…writepage")` as the first line of
    /// the body. RFC 0007 §Lock-order ladder.
    fn writepage(&self, pgoff: u64, buf: &[u8; 4096]) -> Result<(), i64>;

    /// Optional readahead hint. Called by the page-cache fault path
    /// on a sequential-access miss to issue speculative `readpage`s
    /// for pages `[start, start + nr_pages)`.
    ///
    /// Default: no-op — appropriate for non-block filesystems
    /// (ramfs, tarfs) whose pages are already resident, and for any
    /// FS that hasn't implemented a readahead policy yet. The
    /// default body still calls [`assert_no_spinlocks_held`] so a
    /// caller that violates the invariant trips here too — even
    /// though the no-op default does no I/O, the call site is the
    /// API surface and the assertion forms a contract that survives
    /// future readahead implementations.
    ///
    /// ext2's impl will issue up to `RA_WINDOW` (8 pages) of
    /// speculative readpages on a sequential miss (#741, with the
    /// `ra_state` heuristic).
    fn readahead(&self, _start: u64, _nr_pages: u32) {
        assert_no_spinlocks_held("AddressSpaceOps::readahead (default no-op)");
    }

    /// Truncate-down hook. Called by the page-cache `truncate_below`
    /// driver when `i_size` shrinks, *after* the cache has parked
    /// every `PG_WRITEBACK` page in the truncated range and
    /// snapshot-evicted the cached pages, and *before* the FS frees
    /// the underlying on-disk blocks.
    ///
    /// Default: no-op — the cache walks itself; non-block FSes
    /// (ramfs, tarfs) have no on-disk metadata to update.
    ///
    /// ext2's impl will hook this from `setattr(size)` to release
    /// the indirect-block / data-block ranges past `new_size` after
    /// the cache has finished parking on `PG_WRITEBACK` (#752).
    ///
    /// The default body calls [`assert_no_spinlocks_held`] for the
    /// same reason `readahead` does.
    fn truncate_below(&self, _new_size: u64) {
        assert_no_spinlocks_held("AddressSpaceOps::truncate_below (default no-op)");
    }
}

#[cfg(test)]
mod tests {
    //! Host unit tests for the trait surface itself. Concrete
    //! `AddressSpaceOps` impls live alongside their FS drivers; the
    //! tests here exercise (a) that a stub impl can be constructed
    //! and dispatched through `Arc<dyn AddressSpaceOps>`, and (b)
    //! that the default `readahead` / `truncate_below` bodies are
    //! genuinely no-ops (they don't panic on entry from a host
    //! caller with no spinlock held).

    use super::*;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};

    /// Test stand-in for a real FS-backed `AddressSpaceOps`. Stores
    /// page contents in memory and counts every method invocation
    /// so the page-cache unit tests can verify dispatch went through
    /// the trait rather than short-circuited.
    pub(crate) struct MemoryBackedOps {
        pages: spin::Mutex<Vec<[u8; 4096]>>,
        pub readpage_calls: AtomicU32,
        pub writepage_calls: AtomicU32,
        pub readahead_calls: AtomicU32,
        pub truncate_calls: AtomicU32,
    }

    impl MemoryBackedOps {
        pub(crate) fn with_pages(n: usize) -> Arc<Self> {
            let mut v = Vec::with_capacity(n);
            for i in 0..n {
                let mut buf = [0u8; 4096];
                // Mark the first byte with the page index so a
                // readpage round-trip can be observed.
                buf[0] = i as u8;
                v.push(buf);
            }
            Arc::new(Self {
                pages: spin::Mutex::new(v),
                readpage_calls: AtomicU32::new(0),
                writepage_calls: AtomicU32::new(0),
                readahead_calls: AtomicU32::new(0),
                truncate_calls: AtomicU32::new(0),
            })
        }
    }

    impl AddressSpaceOps for MemoryBackedOps {
        fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64> {
            assert_no_spinlocks_held("MemoryBackedOps::readpage");
            self.readpage_calls.fetch_add(1, Ordering::Relaxed);
            let pages = self.pages.lock();
            match pages.get(pgoff as usize) {
                Some(page) => {
                    buf.copy_from_slice(page);
                    Ok(4096)
                }
                None => Ok(0),
            }
        }

        fn writepage(&self, pgoff: u64, buf: &[u8; 4096]) -> Result<(), i64> {
            assert_no_spinlocks_held("MemoryBackedOps::writepage");
            self.writepage_calls.fetch_add(1, Ordering::Relaxed);
            let mut pages = self.pages.lock();
            if let Some(page) = pages.get_mut(pgoff as usize) {
                page.copy_from_slice(buf);
                Ok(())
            } else {
                // Out-of-range writepage: emulate -ENOSPC.
                Err(28)
            }
        }

        fn readahead(&self, _start: u64, _nr_pages: u32) {
            assert_no_spinlocks_held("MemoryBackedOps::readahead");
            self.readahead_calls.fetch_add(1, Ordering::Relaxed);
        }

        fn truncate_below(&self, _new_size: u64) {
            assert_no_spinlocks_held("MemoryBackedOps::truncate_below");
            self.truncate_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn dyn_dispatch_through_arc() {
        let ops: Arc<dyn AddressSpaceOps> = MemoryBackedOps::with_pages(2);
        let mut buf = [0u8; 4096];
        assert_eq!(ops.readpage(0, &mut buf).unwrap(), 4096);
        assert_eq!(buf[0], 0);
        assert_eq!(ops.readpage(1, &mut buf).unwrap(), 4096);
        assert_eq!(buf[0], 1);
    }

    #[test]
    fn readpage_past_eof_returns_zero() {
        let ops: Arc<dyn AddressSpaceOps> = MemoryBackedOps::with_pages(1);
        let mut buf = [0xffu8; 4096];
        // pgoff 5 is past EOF (only 1 page exists).
        assert_eq!(ops.readpage(5, &mut buf).unwrap(), 0);
        // Buf untouched on Ok(0) — RFC 0007 §AddressSpaceOps:
        // pages past EOF are zero-filled by the caller.
        assert_eq!(buf[0], 0xff);
    }

    #[test]
    fn writepage_round_trips_through_readpage() {
        let backing = MemoryBackedOps::with_pages(1);
        let ops: Arc<dyn AddressSpaceOps> = backing.clone();
        let payload = [0xa5u8; 4096];
        ops.writepage(0, &payload).unwrap();
        let mut readback = [0u8; 4096];
        ops.readpage(0, &mut readback).unwrap();
        assert_eq!(readback, payload);
        assert_eq!(backing.readpage_calls.load(Ordering::Relaxed), 1);
        assert_eq!(backing.writepage_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn writepage_out_of_range_returns_errno() {
        let ops: Arc<dyn AddressSpaceOps> = MemoryBackedOps::with_pages(1);
        let payload = [0u8; 4096];
        // pgoff 99 is past the backing store.
        assert_eq!(ops.writepage(99, &payload), Err(28));
    }

    /// Default `readahead` is a no-op: it does not panic, does not
    /// touch any state, and returns. The implementor wiring in
    /// MemoryBackedOps overrides the default; to exercise the
    /// default itself we use a fresh type that does *not* override.
    struct DefaultOnlyOps;
    impl AddressSpaceOps for DefaultOnlyOps {
        fn readpage(&self, _pgoff: u64, _buf: &mut [u8; 4096]) -> Result<usize, i64> {
            Ok(0)
        }
        fn writepage(&self, _pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
            Ok(())
        }
        // readahead and truncate_below intentionally not overridden —
        // the default trait bodies are exercised by the tests below.
    }

    #[test]
    fn default_readahead_is_no_op() {
        let ops: Arc<dyn AddressSpaceOps> = Arc::new(DefaultOnlyOps);
        // No state to observe — the assertion is that this returns
        // without panicking and without touching any caller state.
        ops.readahead(0, 8);
        ops.readahead(123, 0);
    }

    #[test]
    fn default_truncate_below_is_no_op() {
        let ops: Arc<dyn AddressSpaceOps> = Arc::new(DefaultOnlyOps);
        ops.truncate_below(0);
        ops.truncate_below(u64::MAX);
    }

    #[test]
    fn trait_object_is_send_sync() {
        // Compile-time check that `Arc<dyn AddressSpaceOps>` is
        // Send + Sync (via the trait's `: Send + Sync` bound).
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<dyn AddressSpaceOps>>();
    }

    #[test]
    fn multiple_arcs_share_backing() {
        // The `Arc<dyn AddressSpaceOps>` storage discipline relies
        // on cheap clone — a writeback daemon clones the cache's
        // ops Arc into its own task without forcing a new allocation.
        let backing = MemoryBackedOps::with_pages(1);
        let a: Arc<dyn AddressSpaceOps> = backing.clone();
        let b: Arc<dyn AddressSpaceOps> = backing.clone();
        let payload = [0x5au8; 4096];
        a.writepage(0, &payload).unwrap();
        let mut buf = [0u8; 4096];
        b.readpage(0, &mut buf).unwrap();
        assert_eq!(buf, payload);
        // Both Arcs observed the same call counters.
        assert_eq!(backing.readpage_calls.load(Ordering::Relaxed), 1);
        assert_eq!(backing.writepage_calls.load(Ordering::Relaxed), 1);
    }

    /// Reachable so the `page_cache` sibling module's tests can
    /// build a stub `Arc<dyn AddressSpaceOps>` without re-deriving
    /// the same harness.
    pub(crate) fn fresh_ops() -> Arc<dyn AddressSpaceOps> {
        MemoryBackedOps::with_pages(4)
    }

    /// Sanity: `Vec` import is exercised so it doesn't bit-rot if
    /// the test module's other call sites move.
    #[test]
    fn vec_import_used() {
        let _v: Vec<u8> = vec![0u8; 1];
    }
}

#[cfg(test)]
pub(crate) use tests::{fresh_ops, MemoryBackedOps};
