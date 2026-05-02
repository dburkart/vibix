//! ext2 [`AddressSpaceOps`] implementation — the page-cache hook the
//! generic per-inode page cache calls on read miss / writeback /
//! readahead / truncate.
//!
//! RFC 0007 §`AddressSpaceOps` and §Tail-page zeroing are the normative
//! spec. This module is **Workstream C / issue #749**: it lands the
//! `readpage` path only. The other three trait methods (`writepage`,
//! `truncate_below`, `readahead`) are deliberately stubbed out here:
//!
//! - `writepage` returns `Err(EROFS)` — issue #750 lands the real
//!   buffer-cache writeback. Until then a forced-RO behaviour is
//!   strictly safer than `unimplemented!()`-panic, because a future
//!   page-fault path that wires `MAP_SHARED` writeback (#746/#755) can
//!   exercise the writepage call site without bringing the kernel down;
//!   the daemon will see `EROFS` and bump `wb_err`, which is the
//!   correct user-visible behaviour for "this filesystem doesn't
//!   support writeback yet".
//! - `truncate_below` is left at the trait default (no-op + spinlock
//!   assert). Issue #751 will replace it.
//! - `readahead` is left at the trait default (no-op + spinlock
//!   assert). Issue #752 will replace it.
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

use crate::debug_lockdep::assert_no_spinlocks_held;
use crate::fs::ext2::indirect::{resolve_block, Geometry, WalkError};
use crate::fs::ext2::Ext2Super;
use crate::fs::{EIO, EROFS};
use crate::mem::aops::AddressSpaceOps;

use super::file::build_metadata_map;
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

    fn writepage(&self, _pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
        // RFC 0007 §Lock-order ladder: every method body asserts no
        // spinlocks at entry, even the stubbed-out ones — the
        // assertion is part of the trait contract, not the work.
        assert_no_spinlocks_held("Ext2Aops::writepage (stub — #750)");
        // Issue #750 lands the real buffer-cache writeback chain.
        // Until then surface `EROFS` so a `MAP_SHARED` writeback
        // attempt (e.g. via the page-fault path that #746 / #755
        // wires) bumps `wb_err` and surfaces a deterministic errno
        // to userspace, rather than panicking the kernel.
        Err(EROFS)
    }

    // `readahead` and `truncate_below` left at the trait defaults —
    // both are no-op + `assert_no_spinlocks_held`. Issue #751 lands
    // `truncate_below`; issue #752 lands `readahead`.
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
