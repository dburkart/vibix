//! ext2 [`AddressSpaceOps`] implementation — the page-cache hook the
//! generic per-inode page cache calls on read miss / writeback /
//! readahead / truncate.
//!
//! RFC 0007 §`AddressSpaceOps` and §Tail-page zeroing are the normative
//! spec. This module lands all four trait methods:
//!
//! - `readpage` (issue #749) — parsed sparse / dense / past-EOF logic
//!   in [`Ext2Aops::readpage`].
//! - `writepage` (issue #750) — split-the-page-into-blocks-and-
//!   allocate-on-extend in [`Ext2Aops::writepage`].
//! - `readahead` (issue #752) — speculative buffer-cache prefetch over
//!   `[start, start + nr_pages)` driven by the page cache's per-inode
//!   `ra_state` heuristic (#741); see [`Ext2Aops::readahead`].
//! - `truncate_below` (issue #751) — drop every page strictly above
//!   `new_size` from the per-inode page cache and park on
//!   `PG_WRITEBACK` for any in-flight `writepage`s that overlap the
//!   truncated tail. The on-disk block-free walk that follows is
//!   driven by `setattr` itself ([`super::setattr`]) — `truncate_below`
//!   only owns the page-cache half of the truncate so the block-free
//!   path can stay an `RMW + flush_inode_slot` transaction with no
//!   writeback contention (RFC 0007 §Truncate, unmap, MADV_DONTNEED).
//!
//! # Pipeline (`readpage`)
//!
//! For a 4 KiB file page at `pgoff`, the impl:
//!
//! 1. Snapshots `(i_size, i_block[15])` out of the inode metadata lock
//!    (`Ext2InodeMeta`) under a brief read-guard, **before** any
//!    `bread`. Holding the metadata lock across blocking I/O would
//!    serialise every concurrent `stat(2)` against the slowest reader.
//! 2. If `pgoff` is entirely past `i_size` (i.e. `pgoff * 4096 >=
//!    i_size`), returns `Ok(0)` and leaves `buf` untouched per the
//!    `AddressSpaceOps::readpage` contract.
//! 3. Otherwise, computes the `[file_lo .. file_hi)` byte window
//!    inside the page that lies within `i_size`, where
//!    `file_hi = min(pgoff*4096 + 4096, i_size)` and `file_lo =
//!    pgoff*4096`.
//! 4. Walks each FS-block-sized chunk inside that window via
//!    [`super::indirect::resolve_block`]:
//!    - `Ok(Some(abs))` — `bread` and memcpy into `buf` at the
//!      page-relative offset. Sub-block alignment matters for the
//!      head/tail of the window when `block_size > 4096` would be
//!      possible (it isn't on legal ext2 — block sizes are 1024, 2048,
//!      or 4096 — but the arithmetic is written to handle any
//!      `block_size <= 4096` evenly).
//!    - `Ok(None)` — sparse hole. Zero-fill the chunk inside `buf`.
//!    - `Err(WalkError::Io)` → `EIO`.
//!    - `Err(WalkError::Corrupt)` → `EIO` (the upstream walker also
//!      forces the mount RO via the corrupt-pointer detector; the
//!      readpage caller observes a faithful errno regardless).
//! 5. Zero-fills the **tail** `[file_hi - pgoff*4096 .. 4096)` of
//!    `buf`. RFC 0007 §Tail-page zeroing: every byte past `i_size`
//!    inside a partially-in-file page is zero so a `read()` of the
//!    cached page returns POSIX-compliant zeros without the syscall
//!    layer having to compute the tail again.
//! 6. Returns `Ok(4096)` — the impl always populates the full page
//!    when any byte was in-file. The trait's "byte count" is the
//!    populated byte count; for a partial-tail page that's still 4096
//!    because the tail zero-fill is part of the populate contract,
//!    not a short-read indication. This matches the wording in RFC
//!    0007 §`AddressSpaceOps` ("the caller pre-zeroes only when the
//!    impl returns `Ok(0)`").
//!
//! # Errno table (RFC 0007 §Errno table)
//!
//! - `EIO` — buffer-cache read failure (`BlockError::*`), or the
//!   indirect walker returned [`super::indirect::WalkError::Io`] /
//!   [`super::indirect::WalkError::Corrupt`].
//! - `Ok(0)` — `pgoff * 4096 >= i_size`. Pages entirely past EOF; the
//!   page-cache caller pre-zeroes.
//! - `Ok(4096)` — at least one byte of `buf` was in-file (data,
//!   sparse-hole zero, or tail zero) and the page is fully populated.
//!
//! The mount being torn down (`Weak::upgrade()` returns `None` for
//! either `super_ref` or the inode lookup) surfaces as `EIO` — by the
//! time a `readpage` is in flight the inode that owns this Ops has
//! lost its backing storage, which is the same observable a real
//! storage failure would produce.
//!
//! # Lock-order ladder (RFC 0007)
//!
//! `assert_no_spinlocks_held("Ext2Aops::readpage")` is the first line
//! of the body. The page cache drops its level-4 index mutex before
//! calling here, so the assert is the contract enforcement point: if
//! any future caller forgets to drop the index mutex (or tries to call
//! `readpage` from inside a spin-locked critical section), the assert
//! fires before we issue any buffer-cache `bread`.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::debug_lockdep::assert_no_spinlocks_held;
use crate::fs::ext2::indirect::{
    resolve_block, Geometry, MetadataMap, WalkError, EXT2_DIND_BLOCK, EXT2_DIRECT_BLOCKS,
    EXT2_IND_BLOCK, EXT2_TIND_BLOCK,
};
use crate::fs::ext2::Ext2Super;
use crate::fs::{EFBIG, EIO, EROFS};
use crate::mem::aops::AddressSpaceOps;

use super::balloc::{alloc_block, free_block};
use super::disk::EXT2_N_BLOCKS;
use super::file::{build_metadata_map, flush_inode_slot, validate_existing_pointer};
use super::inode::Ext2Inode;

/// Page size the page cache deals in. Matches `crate::mem::PAGE_SIZE`
/// on x86_64 (4 KiB); duplicated here as a `const` because the
/// `AddressSpaceOps::readpage` signature already encodes the size in
/// `&mut [u8; 4096]` and we want a single source of truth that's
/// trivially greppable from this module's docs.
const PAGE_SIZE: u64 = 4096;

/// ext2's [`AddressSpaceOps`] implementation.
///
/// Holds [`Weak`] references to the per-mount [`Ext2Super`] and the
/// in-memory [`Ext2Inode`] this Ops is bound to. Both are weak so a
/// dropped mount or a dropped inode cleanly tears the cache's strong
/// `Arc<dyn AddressSpaceOps>` down without keeping the FS alive past
/// its user-visible lifetime — matching the inode-binding rule (RFC
/// 0007 §Inode-binding rule): a future inode reincarnation gets its
/// own distinct `PageCache` against its own distinct `Ext2Aops`.
///
/// # Construction
///
/// `Ext2Aops` is built by the publication path that hands a fresh
/// [`Ext2Inode`] to the VFS — see [`Ext2Aops::new`]. The Ops Arc is
/// installed on the [`crate::fs::vfs::inode::Inode`] via
/// [`crate::fs::vfs::inode::Inode::set_aops`] before the inode
/// becomes reachable from userspace, so the install-once invariant
/// (RFC 0007 §Inode-binding rule) holds by construction.
///
/// Wave-1 (this issue) only constructs `Ext2Aops` from tests — the
/// real publication wiring lands with the Workstream-D consumers
/// (`FileOps::mmap` in #753, `FileOps::read` cache-routing in #754).
/// The struct shape is finalised here so those follow-ups don't need
/// to revise the type's surface.
pub struct Ext2Aops {
    pub super_ref: Weak<Ext2Super>,
    pub inode_ref: Weak<Ext2Inode>,
}

impl Ext2Aops {
    /// Build an `Ext2Aops` bound to `(super_, ext2_inode)`. The Arc is
    /// returned ready to install via
    /// [`crate::fs::vfs::inode::Inode::set_aops`] — both arguments
    /// are downgraded to `Weak` so the Ops never pins the mount or
    /// the inode past their user-visible lifetimes.
    pub fn new(super_: &Arc<Ext2Super>, ext2_inode: &Arc<Ext2Inode>) -> Arc<Self> {
        Arc::new(Self {
            super_ref: Arc::downgrade(super_),
            inode_ref: Arc::downgrade(ext2_inode),
        })
    }
}

impl AddressSpaceOps for Ext2Aops {
    fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64> {
        // RFC 0007 §Lock-order ladder: every method on this trait
        // must call `assert_no_spinlocks_held` as its very first
        // statement so a caller that forgot to drop a spinlock trips
        // here before issuing any blocking I/O.
        assert_no_spinlocks_held("Ext2Aops::readpage");

        // Upgrade the weak handles. A `None` here means the mount or
        // the inode has been torn down out from under the cache; the
        // page cache will treat this as a faithful filler error and
        // surface `EIO` to the faulting task via
        // `PageCache::abandon_locked_stub`.
        let super_ref = self.super_ref.upgrade().ok_or(EIO)?;
        let ext2_inode = self.inode_ref.upgrade().ok_or(EIO)?;

        // Snapshot the metadata fields we need (size + i_block) under
        // the inode's read-guard, then drop the guard before any
        // blocking `bread`. The pattern mirrors `read_file_at` —
        // holding the metadata lock across block I/O would block
        // every concurrent `stat(2)` for the duration of the
        // slowest reader.
        let (size, i_block) = {
            let meta = ext2_inode.meta.read();
            (meta.size, meta.i_block)
        };

        // Page entirely past EOF — the trait says return `Ok(0)` and
        // leave `buf` untouched. The page-cache caller is responsible
        // for the pre-zero in this case.
        let page_lo = pgoff.checked_mul(PAGE_SIZE).ok_or(EIO)?;
        if page_lo >= size {
            return Ok(0);
        }
        // The exclusive upper bound of the file-content window that
        // overlaps this page. Bounded by both `i_size` (so the tail
        // gets zero-filled) and the page's own end (so a small file
        // that fits in fewer than 4096 bytes tail-zeroes everything
        // past `size`).
        let page_hi_full = page_lo.saturating_add(PAGE_SIZE);
        let page_hi_in_file = core::cmp::min(page_hi_full, size);
        debug_assert!(page_hi_in_file > page_lo);

        // Build the geometry + metadata-forbidden map fresh per
        // call. The cost is `O(groups)` (a few bgdt entries on a
        // typical mount) and the alternative — caching the map on
        // `Ext2Super` — is tracked as a perf follow-up under the
        // same TODO `read_file_at` carries.
        let (s_first_data_block, s_blocks_count) = {
            let sb = super_ref.sb_disk.lock();
            (sb.s_first_data_block, sb.s_blocks_count)
        };
        let geom =
            Geometry::new(super_ref.block_size, s_first_data_block, s_blocks_count).ok_or(EIO)?;
        let md = build_metadata_map(&super_ref);

        let block_size = super_ref.block_size as u64;
        debug_assert!(block_size > 0, "mount validated block_size != 0");

        // Iterate FS-block-sized chunks across the in-file window.
        // For block_size >= 4096 (i.e. 4096 — ext2's max legal block
        // size) each page covers exactly one disk block; for
        // block_size < 4096 (1024 / 2048) the page spans multiple
        // blocks. The loop is written to handle both uniformly.
        let mut cur = page_lo;
        while cur < page_hi_in_file {
            let logical_u64 = cur / block_size;
            // ext2 caps `s_blocks_count` at `u32::MAX`; a logical
            // index past that is a corrupted geometry we treat as
            // EIO at the read site (the walker would also reject
            // it via its own bounds check).
            let logical: u32 = logical_u64.try_into().map_err(|_| EIO)?;

            // In-block offset / chunk size: bound by the block's
            // tail and the in-file window's tail.
            let in_block = (cur % block_size) as usize;
            let block_remaining = block_size as usize - in_block;
            let window_remaining = (page_hi_in_file - cur) as usize;
            let chunk = core::cmp::min(block_remaining, window_remaining);
            let buf_off = (cur - page_lo) as usize;

            match resolve_block(
                &super_ref.cache,
                super_ref.device_id,
                &geom,
                &md,
                &i_block,
                logical,
                None,
            ) {
                Ok(Some(abs)) => {
                    let bh = super_ref
                        .cache
                        .bread(super_ref.device_id, abs as u64)
                        .map_err(|_| EIO)?;
                    let data = bh.data.read();
                    debug_assert!(in_block + chunk <= data.len());
                    debug_assert!(buf_off + chunk <= buf.len());
                    buf[buf_off..buf_off + chunk]
                        .copy_from_slice(&data[in_block..in_block + chunk]);
                }
                Ok(None) => {
                    // Sparse hole. RFC 0007 §Errno table sparse-hole
                    // row: zero-fill the chunk inside `buf` rather
                    // than relying on the caller's pre-zero — the
                    // caller only pre-zeroes on `Ok(0)`, which is
                    // the past-EOF path, not the sparse-hole path.
                    debug_assert!(buf_off + chunk <= buf.len());
                    for b in &mut buf[buf_off..buf_off + chunk] {
                        *b = 0;
                    }
                }
                Err(WalkError::Io) => return Err(EIO),
                Err(WalkError::Corrupt) => {
                    // RFC 0004 §Security: a corrupt pointer means
                    // the on-disk image is lying to us. Surface as
                    // `EIO`; the walker's own corruption detector is
                    // what trips the force-RO latch on the write
                    // path (we're a read path, so the latch is
                    // out-of-band here).
                    return Err(EIO);
                }
            }

            cur += chunk as u64;
        }

        // RFC 0007 §Tail-page zeroing: zero `[i_size .. page_end)`
        // inside `buf` so a subsequent `read()` of the cached page
        // returns POSIX-compliant zeros without the syscall layer
        // having to recompute the tail. Skipped when the in-file
        // window already filled the whole page.
        if page_hi_in_file < page_hi_full {
            let tail_off = (page_hi_in_file - page_lo) as usize;
            debug_assert!(tail_off <= buf.len());
            for b in &mut buf[tail_off..] {
                *b = 0;
            }
        }

        Ok(PAGE_SIZE as usize)
    }

    /// Write `buf` back to file page `pgoff` via the buffer cache.
    ///
    /// Splits the 4 KiB page into FS-block-sized fragments (1, 2, or
    /// 4 fragments depending on `block_size ∈ {4096, 2048, 1024}`),
    /// drives each fragment through the bitmap → indirect → data
    /// allocation chain (RFC 0004 §Write Ordering — same ordering as
    /// `write_file_at`), then RMW-overlays the user bytes through the
    /// buffer cache and `sync_dirty_buffer`s. `i_blocks` and `i_size`
    /// are bumped *only after every per-block write succeeds*.
    ///
    /// On any per-block failure (allocator-out-of-space, indirect-
    /// pointer corruption, buffer-cache I/O), the impl rolls back
    /// every block this writepage allocated — `free_block` for the
    /// data block + each newly-allocated indirect-pointer block, and
    /// clears the slot that pointed at it (either an `i_block[]` slot
    /// in memory or a freshly-RMW-zeroed slot inside the parent
    /// indirect block). The on-disk and in-memory views are restored
    /// to the pre-call state; the caller (writeback daemon) bumps
    /// `mapping.wb_err` on the returned errno (errseq surface).
    ///
    /// # Errno table
    ///
    /// - [`EROFS`] — RO mount (user-requested or feature-forced) or
    ///   the runtime force-RO latch tripped (RFC 0004 §Security).
    ///   Surfaces directly without consulting the page contents.
    /// - [`EFBIG`] — `pgoff * 4096` overflows `u64`, or the logical
    ///   block index lies past triple-indirect.
    /// - [`EIO`] — buffer-cache read/write failure or attacker-forged
    ///   pointer in an existing indirect chain (the same forgery
    ///   detector the read walker enforces).
    /// - Any errno surfaced by [`alloc_block`] (typically `ENOSPC`).
    ///
    /// # Lock-order
    ///
    /// `assert_no_spinlocks_held` first. The metadata write-lock on
    /// [`Ext2Inode::meta`] is held across the entire allocation +
    /// write + flush sequence so a racing truncate / write cannot
    /// interleave block-pointer mutations with ours.
    fn writepage(&self, pgoff: u64, buf: &[u8; 4096]) -> Result<(), i64> {
        assert_no_spinlocks_held("Ext2Aops::writepage");

        let super_ref = self.super_ref.upgrade().ok_or(EIO)?;
        let ext2_inode = self.inode_ref.upgrade().ok_or(EIO)?;

        // RO / forced-RO / latched-RO mount → don't even consider the
        // page contents. The writeback daemon will bump `wb_err` on
        // this errno (RFC 0007 §`PageCache`, errseq pattern).
        if !super_ref.is_writable() {
            return Err(EROFS);
        }

        let block_size = super_ref.block_size as u64;
        debug_assert!(block_size > 0, "mount validated block_size != 0");

        // Page byte-offset window. `pgoff * 4096` overflowing surfaces
        // as EFBIG — a structurally too-large file index can't fit in
        // ext2's logical-block u32 either, so the errno lines up.
        let page_lo = pgoff.checked_mul(PAGE_SIZE).ok_or(EFBIG)?;
        let page_hi = page_lo.checked_add(PAGE_SIZE).ok_or(EFBIG)?;

        // Geometry + metadata-forbidden map. Same construction as
        // `readpage` / `write_file_at`; see those modules for the
        // perf TODO around caching this on `Ext2Super`.
        let (s_first_data_block, s_blocks_count, s_inodes_per_group) = {
            let sb = super_ref.sb_disk.lock();
            (
                sb.s_first_data_block,
                sb.s_blocks_count,
                sb.s_inodes_per_group,
            )
        };
        let geom =
            Geometry::new(super_ref.block_size, s_first_data_block, s_blocks_count).ok_or(EIO)?;
        let md = build_metadata_map(&super_ref);

        // Hint group for `alloc_block`: data-locality wants new blocks
        // to land in the same group as the inode. Mirrors the
        // computation in `write_file_at`.
        let inode_group = if s_inodes_per_group == 0 {
            0
        } else {
            (ext2_inode.ino - 1) / s_inodes_per_group
        };

        // Hold the metadata write-lock across the whole sequence — see
        // the doc on `write_file_at` for the rationale (serialise
        // against truncate / racing extend writes so block-pointer
        // mutations don't trample each other).
        let mut meta = ext2_inode.meta.write();

        // Track every allocation done during this writepage so we can
        // unwind on a per-block failure. The Vec sees at most
        // ~5 events per call (4 leaf data blocks + 1 single-indirect
        // pointer block on a 1 KiB-block fs); for normal 4 KiB-block
        // mounts it sees at most one event.
        let mut events: Vec<AllocEvent> = Vec::new();
        let mut bumped_blocks_512: u64 = 0;

        // Walk the page in FS-block-sized fragments. Use a local
        // closure-style fold so a per-block error short-circuits to
        // the rollback path.
        let result: Result<(), i64> = (|| {
            let mut cur = page_lo;
            while cur < page_hi {
                let logical_u64 = cur / block_size;
                let logical: u32 = logical_u64.try_into().map_err(|_| EFBIG)?;
                let in_block = (cur % block_size) as usize;
                let chunk = (block_size as usize) - in_block;
                debug_assert!(chunk > 0);
                let buf_off = (cur - page_lo) as usize;
                debug_assert!(buf_off + chunk <= buf.len());

                // Resolve / allocate the underlying disk block. The
                // allocation path records each step in `events` so a
                // failure later in this iteration (or a later
                // iteration) can roll back.
                let data_blk = ensure_block_for_writepage(
                    &super_ref,
                    &geom,
                    &md,
                    &mut meta.i_block,
                    logical,
                    inode_group,
                    &mut events,
                    &mut bumped_blocks_512,
                )?;

                // RMW the data block: bread, overlay our chunk at
                // `in_block`, mark dirty, sync.
                let bh = super_ref
                    .cache
                    .bread(super_ref.device_id, data_blk as u64)
                    .map_err(|_| EIO)?;
                {
                    let mut data = bh.data.write();
                    debug_assert!(in_block + chunk <= data.len());
                    data[in_block..in_block + chunk]
                        .copy_from_slice(&buf[buf_off..buf_off + chunk]);
                }
                super_ref.cache.mark_dirty(&bh);
                super_ref.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;

                cur += chunk as u64;
            }
            Ok(())
        })();

        if let Err(e) = result {
            // Roll back every allocation we did this call. Any data
            // already overlaid into a *pre-existing* block stays —
            // it's the caller's bytes against a block they already
            // owned; clobbering it would lose work the caller
            // committed. Only freshly-allocated blocks are returned.
            rollback_allocations(&super_ref, &mut meta.i_block, &events);
            return Err(e);
        }

        // All per-block writes succeeded. Bump `i_size` (only if the
        // page extends the file — the trait contract is "writepage
        // never shrinks") and `i_blocks`. The mtime/ctime bump
        // matches `write_file_at`'s discipline.
        //
        // Snapshot the pre-mutation values so a `flush_inode_slot`
        // failure can restore the in-memory meta wholesale (CodeRabbit
        // #803: a partial restore that only touched `i_block[]` would
        // leave `size` / `i_blocks` / mtime / ctime visibly enlarged
        // after a flush failure even though the underlying blocks
        // were unwound).
        let old_size = meta.size;
        let old_i_blocks = meta.i_blocks;
        let old_mtime = meta.mtime;
        let old_ctime = meta.ctime;

        let new_size = meta.size.max(page_hi);
        meta.size = new_size;
        meta.i_blocks = meta.i_blocks.saturating_add(bumped_blocks_512 as u32);
        let now = crate::fs::vfs::Timespec::now();
        meta.mtime = now.sec as u32;
        meta.ctime = now.sec as u32;

        // Flush the inode slot. RFC 0004 §Write Ordering: this is
        // *last*, after every data + indirect block has hit the
        // device. A crash before this point leaves readers with the
        // pre-writepage `i_size` (correct, just stale) but every
        // block that was committed is safely on disk and reachable
        // through its parent.
        if let Err(e) = flush_inode_slot(&super_ref, ext2_inode.ino, &meta) {
            // The inode-slot flush failed *after* every data block
            // landed. Free the freshly-allocated blocks so the
            // bitmap / counters don't leak, and revert every field we
            // bumped above so the in-memory meta matches the pre-call
            // state — the user sees the failure via the returned
            // errno; subsequent `getattr` against this inode must not
            // observe phantom-extended size/blocks.
            //
            // (Caveat: `sync_dirty_buffer` returning Err does not
            // strictly prove the on-disk inode slot is unchanged. The
            // codebase-wide convention — `write_file_at`,
            // `setattr`, `link`, `create` — is the same "free + restore"
            // posture; tightening to a force-RO latch on uncertain-
            // durability is tracked as a follow-up rather than fixed
            // piecemeal here.)
            rollback_allocations(&super_ref, &mut meta.i_block, &events);
            meta.size = old_size;
            meta.i_blocks = old_i_blocks;
            meta.mtime = old_mtime;
            meta.ctime = old_ctime;
            return Err(e);
        }

        // The VFS-layer `Inode::meta` mirror is intentionally *not*
        // updated here. `Ext2Aops` doesn't carry an `Inode` weak
        // pointer — the readpage path doesn't need one and adding it
        // for writepage would expand the trait-object footprint
        // wave-3 #753 hasn't yet committed to. The on-disk slot is
        // flushed above, so the next `iget` (or fault-path
        // `Inode::page_cache_or_create`) re-reads the fresh values;
        // a concurrent in-memory `getattr` against the same inode
        // sees the previous size/blocks until that point. That's
        // acceptable for the page-cache writeback path the daemon
        // drives — the daemon doesn't itself depend on the in-memory
        // VFS meta. See follow-up issue captured in the PR body.
        Ok(())
    }

    /// Speculative buffer-cache prefetch for pages
    /// `[start, start + nr_pages)`.
    ///
    /// RFC 0007 §Performance Considerations (readahead) is the normative
    /// spec. The page cache's per-inode `ra_state` (#741) is what
    /// decides `nr_pages`; this impl is the FS-side mechanism that
    /// turns "we expect the next `nr_pages` to fault soon" into "the
    /// data blocks for those pages are resident in the buffer cache by
    /// the time the fault arrives".
    ///
    /// # Strategy: warm the buffer cache, not the page cache
    ///
    /// We `bread` each fs-block underlying every page in the window.
    /// We deliberately do **not** install pages into the per-inode
    /// page cache here:
    ///
    /// 1. The page cache install is the fault path's job (it owns the
    ///    install-once race protocol via [`PG_LOCKED`]). Doing it from
    ///    readahead would either duplicate that protocol or race
    ///    against it.
    /// 2. `Ext2Aops` carries no [`Weak<crate::mem::page_cache::PageCache>`]
    ///    — adding one would expand the trait-object footprint and the
    ///    inode-binding contract beyond what the issue's predecessors
    ///    settled.
    /// 3. Buffer-cache residency is the I/O the fault path actually
    ///    cares about: a `readpage` whose block is already resident
    ///    skips the device read entirely (cache.bread fast path —
    ///    `block::cache`). The user-visible win is the same with much
    ///    less mechanism.
    ///
    /// # Bounds and clamping
    ///
    /// - Pages entirely past `i_size` are skipped. The buffer cache
    ///   doesn't need warming for blocks the fault path won't read.
    /// - `start` is interpreted as the **first** page to prefetch —
    ///   the page cache caller passes `pgoff + 1` for the page that
    ///   triggered the miss (see `note_miss` doc on the "additional
    ///   pages" semantics).
    /// - `nr_pages == 0` is a fast no-op after the spinlock assert.
    ///
    /// # Errors
    ///
    /// **Best-effort.** This is a hint, not a contract. Any errno
    /// observed mid-walk (corrupt indirect pointer, `bread` failure,
    /// torn-down mount) stops the prefetch *for that page* and we move
    /// on; the caller fault — which will happen later, on demand —
    /// gets a faithful errno through `readpage`. We never panic and we
    /// never propagate.
    ///
    /// # Lock-order
    ///
    /// Per RFC 0007 §Lock-order ladder, the impl asserts no spinlock
    /// is held at entry. The page cache caller has dropped its level-4
    /// `PageCache::inner` mutex before invoking us — that's the
    /// "never holds the cache mutex" invariant the issue's tracking
    /// description calls out. We acquire only the inode metadata
    /// `RwLock` (briefly, to snapshot `(size, i_block)`) and then the
    /// buffer cache's `inner` mutex one block at a time inside `bread`.
    fn readahead(&self, start: u64, nr_pages: u32) {
        // RFC 0007 §Lock-order ladder: every method on this trait
        // calls `assert_no_spinlocks_held` as its very first
        // statement. Done even on the `nr_pages == 0` fast path so a
        // caller that holds a spinlock around a "skip" call still
        // trips the contract.
        assert_no_spinlocks_held("Ext2Aops::readahead");

        if nr_pages == 0 {
            return;
        }

        // Best-effort: a torn-down mount or inode is the same shape
        // as a `bread` failure here — readahead is a hint and the
        // upcoming `readpage` will produce the faithful errno when
        // the fault actually arrives. Just bail.
        let Some(super_ref) = self.super_ref.upgrade() else {
            return;
        };
        let Some(ext2_inode) = self.inode_ref.upgrade() else {
            return;
        };

        // Snapshot under the metadata read-guard, then drop. Same
        // pattern as `readpage`: holding `meta` across `bread` would
        // serialise every concurrent `stat(2)` against the slowest
        // readahead.
        let (size, i_block) = {
            let meta = ext2_inode.meta.read();
            (meta.size, meta.i_block)
        };

        // Clamp the window to in-file pages. A `start` already past
        // EOF makes the whole window past EOF — nothing to warm.
        let Some(start_byte) = start.checked_mul(PAGE_SIZE) else {
            return;
        };
        if start_byte >= size {
            return;
        }

        // Geometry + metadata-forbidden map. Same construction as
        // `readpage` — see that body for the perf TODO around caching
        // this on `Ext2Super`.
        let (s_first_data_block, s_blocks_count) = {
            let sb = super_ref.sb_disk.lock();
            (sb.s_first_data_block, sb.s_blocks_count)
        };
        let Some(geom) = Geometry::new(super_ref.block_size, s_first_data_block, s_blocks_count)
        else {
            return;
        };
        let md = build_metadata_map(&super_ref);

        let block_size = super_ref.block_size as u64;
        debug_assert!(block_size > 0, "mount validated block_size != 0");

        // Walk page-by-page across `[start, start + nr_pages)`. For
        // each page, walk fs-block-sized fragments inside the page's
        // in-file window and `bread` each resolved block. Sparse
        // holes (`Ok(None)`) need no warming — the fault path's
        // `readpage` zero-fills them inline without touching the
        // buffer cache.
        for i in 0..nr_pages {
            // `start + i` overflowing means the fault stream has
            // walked off the end of u64 pgoff space; nothing
            // sensible to prefetch.
            let Some(pgoff) = start.checked_add(i as u64) else {
                return;
            };
            let Some(page_lo) = pgoff.checked_mul(PAGE_SIZE) else {
                return;
            };
            if page_lo >= size {
                // Past EOF — every subsequent page is also past EOF
                // (size is a non-decreasing snapshot here). Stop.
                return;
            }
            let page_hi_full = page_lo.saturating_add(PAGE_SIZE);
            let page_hi_in_file = core::cmp::min(page_hi_full, size);

            let mut cur = page_lo;
            while cur < page_hi_in_file {
                let logical_u64 = cur / block_size;
                // Logical-block index past `u32::MAX` is a corrupted
                // geometry; the readpage path treats it as `EIO`. For
                // best-effort prefetch we just stop walking — the
                // fault that follows will surface the errno.
                let Ok(logical) = u32::try_from(logical_u64) else {
                    return;
                };

                // In-block / window arithmetic mirrors `readpage`.
                // We don't need the `chunk`-relative copy logic, only
                // the advance: a `bread` warms the *whole* fs-block
                // regardless of which bytes inside it we ultimately
                // care about.
                let in_block = (cur % block_size) as usize;
                let block_remaining = block_size as usize - in_block;
                let window_remaining = (page_hi_in_file - cur) as usize;
                let advance = core::cmp::min(block_remaining, window_remaining);

                match resolve_block(
                    &super_ref.cache,
                    super_ref.device_id,
                    &geom,
                    &md,
                    &i_block,
                    logical,
                    None,
                ) {
                    Ok(Some(abs)) => {
                        // Best-effort warm: discard the returned
                        // `Arc<BufferHead>` immediately. The cache's
                        // `clock_ref` bit is what keeps the entry
                        // resident across the eviction sweep; we don't
                        // need to pin the strong reference here, the
                        // upcoming `readpage` will re-`bread` and
                        // observe the cache hit.
                        let _ = super_ref.cache.bread(super_ref.device_id, abs as u64);
                    }
                    Ok(None) => {
                        // Sparse hole — `readpage` zero-fills inline,
                        // nothing on disk to warm.
                    }
                    Err(WalkError::Io) | Err(WalkError::Corrupt) => {
                        // Corrupt or unreachable indirect pointer.
                        // Stop the walk; the fault path's `readpage`
                        // surfaces the errno faithfully when the user
                        // actually demands the byte.
                        return;
                    }
                }

                // `advance` is at least 1 byte for any `block_size >= 1`
                // and any non-empty in-file window; the loop is
                // guaranteed to make progress.
                debug_assert!(advance > 0);
                cur += advance as u64;
            }
        }
    }

    /// Drop every cached page strictly above `new_size` from the
    /// per-inode page cache and wait out any `writepage` in flight
    /// over the truncated tail.
    ///
    /// RFC 0007 §Truncate, unmap, MADV_DONTNEED is the normative spec.
    /// Closes the on-disk UAF surface where the writeback daemon's
    /// `writepage` could otherwise commit stale bytes into blocks the
    /// FS is concurrently freeing: a shrinking `setattr(size = N)`
    /// must not free disk blocks underneath any page whose
    /// `writepage` has not yet returned. The contract this method
    /// honours:
    ///
    /// 1. **Drop cached pages with `pgoff >= ceil(new_size / 4096)`.**
    ///    The page-cache index is updated under its own level-4 mutex
    ///    so the writeback daemon's snapshot can no longer enqueue
    ///    them. The page containing the `new_size` byte itself stays
    ///    cached: it holds bytes both above and below the cut, and
    ///    its tail is the readpage tail-zero rule's job (RFC 0007
    ///    §Tail-page zeroing).
    /// 2. **Park on `PG_WRITEBACK` for every dropped page.** A page
    ///    whose `writepage` is presently in flight survives in the
    ///    snapshot (the cache hands us a strong `Arc<CachePage>` and
    ///    the daemon's own snapshot still holds another). We park on
    ///    [`CachePage::wait_until_writeback_clear`] so the daemon's
    ///    `end_writeback` reaches us before the truncate caller
    ///    proceeds to the on-disk free.
    /// 3. **Return.** The on-disk block-free walk
    ///    ([`super::setattr::truncate_free`]) is driven by `setattr`
    ///    itself, after this returns. Splitting the cache half here
    ///    keeps the block-free path a single inode-slot RMW
    ///    transaction with no writeback contention — RFC 0007
    ///    §Truncate, unmap, MADV_DONTNEED specifies the cache park as
    ///    a strict precondition of the block free, which this method
    ///    discharges.
    ///
    /// # Lock-order
    ///
    /// The `assert_no_spinlocks_held` invariant is the first
    /// statement; the page cache's level-4 mutex is acquired only by
    /// [`PageCache::truncate_below`] and is released before any
    /// `wait_until_writeback_clear` park.
    ///
    /// # Best-effort cache lookup
    ///
    /// `Ext2Aops` carries [`Weak`] handles to its mount and inode. A
    /// torn-down mount, a torn-down inode, or an inode whose VFS
    /// reflection is not in the mount's inode cache (e.g. a unit test
    /// that constructs an `Ext2Aops` directly without `iget`) all
    /// surface here as "no observable page cache to truncate" and
    /// the method becomes a no-op. The `setattr` caller's on-disk
    /// block-free still runs; the page cache, if any was constructed
    /// out-of-band, would simply observe stale `i_size` until its
    /// next own-truncate. This is acceptable because every production
    /// path goes through the `iget` cache, where the mapping is
    /// reachable.
    fn truncate_below(&self, new_size: u64) {
        // RFC 0007 §Lock-order ladder: every method on this trait
        // calls `assert_no_spinlocks_held` as its very first statement.
        assert_no_spinlocks_held("Ext2Aops::truncate_below");

        // The cache-side work is gated on the `page_cache` feature
        // because the `mapping` field on `Inode` is itself gated on
        // that feature (RFC 0007 migration window). Off-feature builds
        // collapse to the trait-default-equivalent no-op; the
        // `setattr` caller's on-disk block-free still runs and
        // remains the security-relevant behaviour. The cfg switch is
        // expected to retire when `page_cache` becomes default.
        #[cfg(feature = "page_cache")]
        {
            // Best-effort: a torn-down mount or inode means there is
            // nothing observable to truncate. The on-disk free is
            // setattr's responsibility and runs unaffected.
            let Some(super_ref) = self.super_ref.upgrade() else {
                return;
            };
            let Some(ext2_inode) = self.inode_ref.upgrade() else {
                return;
            };

            // Resolve the VFS Inode that owns the per-inode page
            // cache. The `inode_cache` on `Ext2Super` is keyed by
            // ext2 ino; the `Weak<Inode>` it stores is the only
            // reachable handle to the VFS inode the cache hangs off.
            // A miss here means the inode has not been published
            // through `iget` (e.g. a direct unit-test construction);
            // the truncate becomes a no-op.
            let vfs_inode = {
                let cache = super_ref.inode_cache.lock();
                cache.get(&ext2_inode.ino).and_then(Weak::upgrade)
            };
            let Some(vfs_inode) = vfs_inode else {
                return;
            };

            // The mapping is published lazily on first read-via-cache
            // / mmap; an inode that has never been faulted has no
            // cache. Either way, no cached pages to drop and no
            // writeback to park on.
            let Some(pc) = vfs_inode.mapping.read().as_ref().map(Arc::clone) else {
                return;
            };

            // Step 1 + 3 (under inner): snapshot every page strictly
            // above `new_size`, remove them from `pages` + `dirty`,
            // and publish the new `i_size` cap. The snapshot keeps
            // the `Arc<CachePage>`s alive so a writepage already in
            // flight can finish.
            let snapshot = pc.truncate_below(new_size);

            // Step 2 (outside inner): park on `PG_WRITEBACK` for
            // each dropped page. The order doesn't matter — every
            // wait is on a disjoint waitqueue. After this loop the
            // snapshot drops, at which point the cache no longer
            // references the truncated tail (only the writeback
            // daemon's own snapshot, if any, is left, and it has
            // already cleared `PG_WRITEBACK` before we returned from
            // the wait).
            for page in &snapshot {
                page.wait_until_writeback_clear();
            }
            // Snapshot drops here.
        }
        // The `_ = new_size` suppresses an unused-variable warning
        // when the body is `cfg`-stripped on `--no-default-features`
        // builds without the `page_cache` flag.
        #[cfg(not(feature = "page_cache"))]
        let _ = new_size;
    }
}

// ---------------------------------------------------------------------------
// writepage internals
// ---------------------------------------------------------------------------

/// One allocation event recorded during [`Ext2Aops::writepage`]. Used
/// solely to rewind on a per-block failure: every event carries enough
/// information to (a) `free_block` the underlying disk block and (b)
/// clear the slot that points at it (either an `i_block[]` slot in
/// memory or a slot inside a previously-allocated indirect block on
/// disk).
#[derive(Debug, Clone, Copy)]
enum AllocEvent {
    /// A direct slot mutation: `i_block[idx] = blk`. Rollback clears
    /// the slot and frees `blk`.
    Direct { idx: usize, blk: u32 },
    /// A top-level indirect pointer install: `i_block[slot_idx] = blk`
    /// where `slot_idx ∈ {EXT2_IND_BLOCK, EXT2_DIND_BLOCK,
    /// EXT2_TIND_BLOCK}`. Rollback clears the slot in `i_block[]`
    /// and frees `blk`.
    TopIndirect { slot_idx: usize, blk: u32 },
    /// A child pointer install at slot `index` inside a previously-
    /// allocated *or* pre-existing indirect block at absolute
    /// `parent_blk`. Rollback RMW-zeroes that on-disk slot and frees
    /// `blk`.
    InnerIndirect {
        parent_blk: u32,
        index: u32,
        blk: u32,
    },
}

/// Number of 512-byte units one fs-block costs (for `i_blocks`
/// bookkeeping). Mirrors the same expression in `write_file_at`.
#[inline]
fn blocks_per_512(geom: &Geometry) -> u64 {
    (geom.block_size / 512) as u64
}

/// Resolve / allocate the data block backing logical block `logical`,
/// recording every allocation event in `events` so a downstream failure
/// can roll back.
///
/// Mirrors [`super::file::ensure_block_allocated`] in shape but
/// records events along the way. The two paths are kept separate
/// rather than refactored together because `write_file_at` is
/// deliberately partial-write-tolerant (a failed block stops the
/// loop without rolling back) while writepage is whole-page-atomic.
#[allow(clippy::too_many_arguments)]
fn ensure_block_for_writepage(
    super_: &Arc<Ext2Super>,
    geom: &Geometry,
    md: &MetadataMap,
    i_block_mut: &mut [u32; EXT2_N_BLOCKS],
    logical: u32,
    hint_group: u32,
    events: &mut Vec<AllocEvent>,
    bumped_512: &mut u64,
) -> Result<u32, i64> {
    let p = geom.ptrs_per_block as u64;
    let direct_limit = EXT2_DIRECT_BLOCKS as u64;
    let single_limit = direct_limit + p;
    let double_limit = single_limit + p * p;
    let triple_limit = double_limit + p * p * p;
    let logical64 = logical as u64;

    let bp512 = blocks_per_512(geom);

    if logical64 < direct_limit {
        let idx = logical as usize;
        let slot = &mut i_block_mut[idx];
        if *slot != 0 {
            validate_existing_pointer(*slot, geom, md)?;
            return Ok(*slot);
        }
        let blk = alloc_and_zero(super_, hint_group)?;
        *slot = blk;
        events.push(AllocEvent::Direct { idx, blk });
        *bumped_512 += bp512;
        Ok(blk)
    } else if logical64 < single_limit {
        let idx0 = (logical64 - direct_limit) as u32;
        let ind = ensure_top_indirect(
            super_,
            i_block_mut,
            EXT2_IND_BLOCK,
            hint_group,
            geom,
            md,
            events,
            bumped_512,
        )?;
        ensure_leaf(super_, ind, idx0, hint_group, geom, md, events, bumped_512)
    } else if logical64 < double_limit {
        let rel = logical64 - single_limit;
        let idx_outer = (rel / p) as u32;
        let idx_inner = (rel % p) as u32;
        let dind = ensure_top_indirect(
            super_,
            i_block_mut,
            EXT2_DIND_BLOCK,
            hint_group,
            geom,
            md,
            events,
            bumped_512,
        )?;
        let ind = ensure_inner_indirect(
            super_, dind, idx_outer, hint_group, geom, md, events, bumped_512,
        )?;
        ensure_leaf(
            super_, ind, idx_inner, hint_group, geom, md, events, bumped_512,
        )
    } else if logical64 < triple_limit {
        let rel = logical64 - double_limit;
        let p_sq = p * p;
        let idx_l0 = (rel / p_sq) as u32;
        let rem = rel % p_sq;
        let idx_l1 = (rem / p) as u32;
        let idx_l2 = (rem % p) as u32;
        let tind = ensure_top_indirect(
            super_,
            i_block_mut,
            EXT2_TIND_BLOCK,
            hint_group,
            geom,
            md,
            events,
            bumped_512,
        )?;
        let dind = ensure_inner_indirect(
            super_, tind, idx_l0, hint_group, geom, md, events, bumped_512,
        )?;
        let ind = ensure_inner_indirect(
            super_, dind, idx_l1, hint_group, geom, md, events, bumped_512,
        )?;
        ensure_leaf(
            super_, ind, idx_l2, hint_group, geom, md, events, bumped_512,
        )
    } else {
        Err(EFBIG)
    }
}

/// Ensure `i_block[slot_idx]` points at a zeroed indirect block. If
/// the slot is already populated, validate the existing pointer
/// (forgery check) and return it. If freshly allocated, push a
/// `TopIndirect` event so a rollback can clear the slot.
#[allow(clippy::too_many_arguments)]
fn ensure_top_indirect(
    super_: &Arc<Ext2Super>,
    i_block_mut: &mut [u32; EXT2_N_BLOCKS],
    slot_idx: usize,
    hint_group: u32,
    geom: &Geometry,
    md: &MetadataMap,
    events: &mut Vec<AllocEvent>,
    bumped_512: &mut u64,
) -> Result<u32, i64> {
    let existing = i_block_mut[slot_idx];
    if existing != 0 {
        validate_existing_pointer(existing, geom, md)?;
        return Ok(existing);
    }
    let blk = alloc_and_zero(super_, hint_group)?;
    i_block_mut[slot_idx] = blk;
    events.push(AllocEvent::TopIndirect { slot_idx, blk });
    *bumped_512 += blocks_per_512(geom);
    Ok(blk)
}

/// Ensure slot `index` of the indirect block at absolute `parent_blk`
/// points at a zeroed child indirect block. If the slot is populated,
/// validate the existing pointer and return it. If freshly allocated,
/// RMW-link the child into the parent (sync) and push an
/// `InnerIndirect` event so a rollback can clear the parent's slot
/// and free the child.
#[allow(clippy::too_many_arguments)]
fn ensure_inner_indirect(
    super_: &Arc<Ext2Super>,
    parent_blk: u32,
    index: u32,
    hint_group: u32,
    geom: &Geometry,
    md: &MetadataMap,
    events: &mut Vec<AllocEvent>,
    bumped_512: &mut u64,
) -> Result<u32, i64> {
    let (existing, bh) = read_indirect_slot(super_, parent_blk, index, geom)?;
    if existing != 0 {
        validate_existing_pointer(existing, geom, md)?;
        return Ok(existing);
    }
    let child = alloc_and_zero(super_, hint_group)?;
    {
        let mut data = bh.data.write();
        let off = (index as usize) * 4;
        debug_assert!(off + 4 <= data.len());
        data[off..off + 4].copy_from_slice(&child.to_le_bytes());
    }
    super_.cache.mark_dirty(&bh);
    if let Err(e) = super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO) {
        // Linking the child into the parent failed at sync time. The
        // child is allocated but unreachable; free it before
        // surfacing. We don't push the InnerIndirect event because
        // the on-disk parent slot was never persisted (we just
        // mutated the in-memory cache page; the next `bread` of
        // `parent_blk` will re-read the on-disk pre-link state if
        // the cache evicts and refills, but if the dirty page sticks
        // in cache the unflushed mutation would be a real leak —
        // call `mark_clean` would be ideal but the cache surface
        // doesn't expose one; revert the byte mutation in-place
        // instead).
        {
            let mut data = bh.data.write();
            let off = (index as usize) * 4;
            data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        let _ = free_block(super_, child);
        return Err(e);
    }
    events.push(AllocEvent::InnerIndirect {
        parent_blk,
        index,
        blk: child,
    });
    *bumped_512 += blocks_per_512(geom);
    Ok(child)
}

/// Ensure slot `index` of the indirect block at absolute `parent_blk`
/// points at a freshly-allocated zeroed data block. Same shape as
/// [`ensure_inner_indirect`] but the child is a data block, not an
/// indirect pointer block. The recorded event type is identical
/// (`InnerIndirect`) — rollback semantics are the same.
#[allow(clippy::too_many_arguments)]
fn ensure_leaf(
    super_: &Arc<Ext2Super>,
    parent_blk: u32,
    index: u32,
    hint_group: u32,
    geom: &Geometry,
    md: &MetadataMap,
    events: &mut Vec<AllocEvent>,
    bumped_512: &mut u64,
) -> Result<u32, i64> {
    let (existing, bh) = read_indirect_slot(super_, parent_blk, index, geom)?;
    if existing != 0 {
        validate_existing_pointer(existing, geom, md)?;
        return Ok(existing);
    }
    let data_blk = alloc_and_zero(super_, hint_group)?;
    {
        let mut data = bh.data.write();
        let off = (index as usize) * 4;
        debug_assert!(off + 4 <= data.len());
        data[off..off + 4].copy_from_slice(&data_blk.to_le_bytes());
    }
    super_.cache.mark_dirty(&bh);
    if let Err(e) = super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO) {
        {
            let mut data = bh.data.write();
            let off = (index as usize) * 4;
            data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        }
        let _ = free_block(super_, data_blk);
        return Err(e);
    }
    events.push(AllocEvent::InnerIndirect {
        parent_blk,
        index,
        blk: data_blk,
    });
    *bumped_512 += blocks_per_512(geom);
    Ok(data_blk)
}

/// Read the pointer at slot `index` out of the indirect block at
/// absolute `abs`, returning both the decoded pointer and the buffer
/// handle so the caller can RMW the same slot on a miss without a
/// second `bread`. Mirrors `file::read_pointer_slot_raw` (kept private
/// to its module — duplicating the four-line helper here is simpler
/// than expanding the file.rs surface).
fn read_indirect_slot(
    super_: &Arc<Ext2Super>,
    abs: u32,
    index: u32,
    geom: &Geometry,
) -> Result<(u32, Arc<crate::block::cache::BufferHead>), i64> {
    debug_assert!(index < geom.ptrs_per_block);
    let bh = super_
        .cache
        .bread(super_.device_id, abs as u64)
        .map_err(|_| EIO)?;
    let val = {
        let data = bh.data.read();
        let off = (index as usize) * 4;
        let slot: [u8; 4] = data[off..off + 4]
            .try_into()
            .expect("indirect pointer slot is exactly 4 bytes");
        u32::from_le_bytes(slot)
    };
    Ok((val, bh))
}

/// Allocate a fresh block via the bitmap allocator and synchronously
/// zero it through the buffer cache. Combined into a single helper so
/// both data and indirect pointer block allocations share the
/// "never link unzeroed bytes into the inode" invariant (RFC 0004
/// §Write Ordering).
fn alloc_and_zero(super_: &Arc<Ext2Super>, hint_group: u32) -> Result<u32, i64> {
    let blk = alloc_block(super_, Some(hint_group))?;
    if let Err(e) = zero_block(super_, blk) {
        // Zeroing failed — return the block to the bitmap so we
        // don't leak. The caller will see the I/O errno and surface
        // it.
        let _ = free_block(super_, blk);
        return Err(e);
    }
    Ok(blk)
}

/// Zero a freshly-allocated block synchronously through the cache.
/// Mirrors `file::zero_block`.
fn zero_block(super_: &Arc<Ext2Super>, abs: u32) -> Result<(), i64> {
    let bh = super_
        .cache
        .bread(super_.device_id, abs as u64)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        for b in data.iter_mut() {
            *b = 0;
        }
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)
}

/// Roll back every allocation event recorded during this writepage.
/// Reverse order so a leaf is unlinked before its parent indirect
/// block. Per-step failures are swallowed — a successful rollback is
/// best-effort: a free or a slot-clear that fails would leak rather
/// than corrupt, and the caller is already on the error path.
fn rollback_allocations(
    super_: &Arc<Ext2Super>,
    i_block_mut: &mut [u32; EXT2_N_BLOCKS],
    events: &[AllocEvent],
) {
    for ev in events.iter().rev() {
        match *ev {
            AllocEvent::Direct { idx, blk } => {
                debug_assert_eq!(i_block_mut[idx], blk);
                i_block_mut[idx] = 0;
                let _ = free_block(super_, blk);
            }
            AllocEvent::TopIndirect { slot_idx, blk } => {
                debug_assert_eq!(i_block_mut[slot_idx], blk);
                i_block_mut[slot_idx] = 0;
                let _ = free_block(super_, blk);
            }
            AllocEvent::InnerIndirect {
                parent_blk,
                index,
                blk,
            } => {
                // RMW-zero the parent slot. If the bread / sync fails
                // we still call `free_block` so the bitmap counter
                // stays honest; the on-disk parent slot is left
                // pointing at a freed block, which `e2fsck` repairs.
                if let Ok(bh) = super_.cache.bread(super_.device_id, parent_blk as u64) {
                    {
                        let mut data = bh.data.write();
                        let off = (index as usize) * 4;
                        if off + 4 <= data.len() {
                            data[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
                        }
                    }
                    super_.cache.mark_dirty(&bh);
                    let _ = super_.cache.sync_dirty_buffer(&bh);
                }
                let _ = free_block(super_, blk);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Host unit tests. The end-to-end pipeline (`readpage` against a
    //! mounted `read_test.img`) is exercised by the QEMU integration
    //! test `kernel/tests/ext2_readpage.rs`; the host tests here cover
    //! the non-I/O surface — the construction shape and the trait-
    //! object plumbing — without standing up an `Ext2Super`.
    //!
    //! Why split: building an `Ext2Super` host-side requires the
    //! `target_os = "none"` block-cache surface, which the host test
    //! profile excludes. The integration test exists for that reason.

    // Compile-time only check: `Arc<Ext2Aops>` coerces to
    // `Arc<dyn AddressSpaceOps>` and is `Send + Sync`.
    #[test]
    fn ext2_aops_is_object_safe_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<super::Ext2Aops>();
        // The trait object form is what `Inode::set_aops` consumes;
        // assert that too so a future refactor that accidentally
        // makes `Ext2Aops` `!Send` trips here, not at the install
        // call site.
        assert_send_sync::<alloc::sync::Arc<dyn super::AddressSpaceOps>>();
    }
}
