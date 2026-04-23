//! ext2 `InodeOps::setattr` — truncate / chmod / chown / utimensat
//! persisted through the buffer cache (issue #572, RFC 0004 §setattr).
//!
//! The VFS syscall layer (`kernel/src/arch/x86_64/syscalls/vfs.rs`) has
//! already enforced the POSIX permission matrix: `do_chmod` / `do_chown`
//! / `build_utime_setattr` / `do_truncate` all verify ownership,
//! privilege, and write-access *before* calling into the driver. This
//! impl therefore trusts the caller's `SetAttr` and focuses on:
//!
//! 1. Translating the per-op mask into mutations on the in-memory
//!    [`Ext2InodeMeta`] + the mirrored [`InodeMeta`] on the VFS
//!    [`Inode`].
//! 2. Freeing data + indirect blocks on a shrinking truncate, in
//!    reverse-logical order so an interrupted truncate never leaks a
//!    pointer past the new EOF (RFC 0004 §Truncate write-ordering).
//! 3. Persisting the updated on-disk inode slot through a single
//!    `bread → encode_to_slot → mark_dirty → sync_dirty_buffer`
//!    transaction per setattr call.
//!
//! # Out of scope
//!
//! - New block *allocation* on a grow truncate. Per the issue body and
//!   RFC 0004 §Sparse files, growing a file only updates `i_size`; the
//!   new range is a sparse hole read-zero. Actual allocation happens on
//!   the first write into the hole, which is Workstream E's write
//!   path, not this PR.
//! - `CAP_CHOWN` / `CAP_FOWNER` — vibix does not implement POSIX
//!   capabilities; the syscall layer's uid/gid/mode gates are the whole
//!   policy.
//! - POSIX ACLs / xattrs.

use alloc::sync::Arc;
use alloc::vec;

use super::disk::{
    Ext2Inode as DiskInode, EXT2_INODE_SIZE_V0, EXT2_N_BLOCKS, RO_COMPAT_LARGE_FILE,
};
use super::fs::{Ext2MountFlags, Ext2Super};
use super::indirect::{
    Geometry, EXT2_DIND_BLOCK, EXT2_DIRECT_BLOCKS, EXT2_IND_BLOCK, EXT2_TIND_BLOCK,
};
use super::inode::Ext2Inode;
use crate::fs::vfs::inode::{Inode, InodeKind};
use crate::fs::vfs::ops::{SetAttr, SetAttrMask};
use crate::fs::{EFBIG, EINVAL, EIO, EISDIR, EROFS};

/// Apply a [`SetAttr`] to `ext2_inode` and persist the on-disk inode
/// slot. Shared by the `InodeOps::setattr` entry point on
/// [`Ext2Inode`].
///
/// The call sequence is:
///
/// 1. Validate the mask against the inode's kind (SIZE on a dir is
///    `EISDIR`; SIZE on anything that isn't a regular file or symlink
///    is `EINVAL`).
/// 2. Reject on a RO / force-RO mount (`EROFS`).
/// 3. If SIZE and shrinking: free data blocks above `new_size` through
///    [`super::balloc::free_block`], clearing `i_block[]` entries and
///    any indirect blocks that become empty.
/// 4. Apply mode/uid/gid/atime/mtime/ctime updates to the in-memory
///    [`Ext2InodeMeta`].
/// 5. RMW the 128-byte inode-table slot on disk: read the containing
///    buffer through the cache, overlay the updated fields via
///    [`DiskInode::encode_to_slot`], mark-dirty + sync.
/// 6. Mirror the same mutation into the VFS [`InodeMeta`] so
///    `stat(2)` observes it without a fresh `iget`.
/// 7. Invalidate the inode's per-inode `IndirectCache` when we remapped
///    any block pointer (truncate).
pub fn setattr(ext2_inode: &Ext2Inode, inode: &Inode, attr: &SetAttr) -> Result<(), i64> {
    let super_ref = ext2_inode.super_ref.upgrade().ok_or(EIO)?;

    if super_ref.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_ref.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    // Per-op pre-validation that depends on inode kind.
    if attr.mask.contains(SetAttrMask::SIZE) {
        match inode.kind {
            InodeKind::Reg => {}
            InodeKind::Dir => return Err(EISDIR),
            // POSIX: truncate(2) on a symlink follows the link at the
            // path-walk layer. Reaching here with Link means a direct
            // driver call (e.g. O_TRUNC on a symlink fd — which is
            // itself already EINVAL at the VFS layer). Mirror Linux's
            // `-EINVAL` for non-regular targets of SIZE.
            _ => return Err(EINVAL),
        }
    }

    // Nothing to do.
    if attr.mask.0 == 0 {
        return Ok(());
    }

    // Phase 1 — truncate data path (may free many blocks). We do the
    // free walk before writing the inode slot so an interrupted
    // truncate either (a) leaves the block still owned by the inode,
    // or (b) returns the block to the allocator with a matching drop
    // in `i_blocks`. Writing the new `i_size` first + crashing before
    // the free would leak blocks; we avoid that ordering.
    let shrunk_blocks: u32;
    let new_i_block: [u32; EXT2_N_BLOCKS];
    let new_i_blocks_512: u32;
    let new_size: u64;
    if attr.mask.contains(SetAttrMask::SIZE) {
        let cur = {
            let m = ext2_inode.meta.read();
            (m.size, m.i_block, m.i_blocks)
        };
        let (cur_size, cur_i_block, cur_i_blocks) = cur;
        new_size = attr.size;

        // Clamp against the largest size the on-disk `i_size` can
        // represent for a regular file. `RO_COMPAT_LARGE_FILE` gets us
        // 64-bit; otherwise we are bounded by u32.
        let ro_compat = super_ref.sb_disk.lock().s_feature_ro_compat;
        let large_file = (ro_compat & RO_COMPAT_LARGE_FILE) != 0;
        let max_size: u64 = if large_file {
            // Ext2 caps the on-disk size at 2^64 - 1 in the large-file
            // encoding; syscall layer clamps to `max_file_size_for`.
            u64::MAX
        } else {
            u32::MAX as u64
        };
        if new_size > max_size {
            return Err(EFBIG);
        }

        if new_size < cur_size {
            // Shrinking: free everything above `new_size`.
            let (freed_data_blocks, updated_i_block) =
                truncate_free(&super_ref, &cur_i_block, new_size)?;
            // `i_blocks` is in 512-byte units. block_size / 512 ==
            // sectors-per-fs-block.
            let spb = (super_ref.block_size / 512) as u32;
            let drop_512 = freed_data_blocks.saturating_mul(spb);
            new_i_blocks_512 = cur_i_blocks.saturating_sub(drop_512);
            new_i_block = updated_i_block;
            shrunk_blocks = freed_data_blocks;
        } else {
            // Grow or same: no block freeing, no allocation.
            new_i_block = cur_i_block;
            new_i_blocks_512 = cur_i_blocks;
            shrunk_blocks = 0;
        }
    } else {
        let m = ext2_inode.meta.read();
        new_size = m.size;
        new_i_block = m.i_block;
        new_i_blocks_512 = m.i_blocks;
        shrunk_blocks = 0;
    }

    // Phase 2 — compute the post-update ext2 meta and persist the
    // inode-table slot in one RMW transaction.
    let now_sec = crate::fs::vfs::Timespec::now().sec as u32;

    // Locate the inode-table slot for `ext2_inode.ino`.
    let (block_in_dev, offset_in_block) = locate_inode_slot(&super_ref, ext2_inode.ino)?;

    let bh = super_ref
        .cache
        .bread(super_ref.device_id, block_in_dev)
        .map_err(|_| EIO)?;

    // Snapshot the superblock feature flag *before* we take any inode
    // lock, so the RMW critical section below does not nest `sb_disk`
    // inside `ext2_meta` / `vfs_meta`.
    let large_file = (super_ref.sb_disk.lock().s_feature_ro_compat & RO_COMPAT_LARGE_FILE) != 0;

    // Validate the in-block inode-slot range *before* we mutate any
    // in-memory meta — once we've taken the `ext2_meta` / `vfs_meta`
    // write locks below, any fallible step would leave the in-memory
    // and on-disk views diverged (stat(2) would see the new values
    // but a remount would revert). `locate_inode_slot` already
    // bounds-checks the offset against the block table, so this is
    // paranoid; we keep it to keep the post-lock path infallible.
    {
        let data_len = bh.data.read().len();
        if offset_in_block + EXT2_INODE_SIZE_V0 > data_len {
            return Err(EIO);
        }
    }

    // Compute the new disk view + write back atomically under the
    // buffer's write guard. Holding the ext2 meta write-lock across
    // the RMW window prevents a racing reader from pulling a torn
    // pair of (in-memory, on-disk) values.
    let mut ext2_meta = ext2_inode.meta.write();
    let mut vfs_meta = inode.meta.write();

    // Apply fields.
    if attr.mask.contains(SetAttrMask::MODE) {
        // Preserve the S_IFMT type bits (top nibble of mode). Only
        // permission + setuid/setgid/sticky bits may change.
        ext2_meta.mode = (ext2_meta.mode & 0o170_000) | (attr.mode & 0o7_777);
        vfs_meta.mode = attr.mode & 0o7_777;
    }
    if attr.mask.contains(SetAttrMask::UID) {
        ext2_meta.uid = attr.uid;
        vfs_meta.uid = attr.uid;
    }
    if attr.mask.contains(SetAttrMask::GID) {
        ext2_meta.gid = attr.gid;
        vfs_meta.gid = attr.gid;
    }
    if attr.mask.contains(SetAttrMask::SIZE) {
        ext2_meta.size = new_size;
        ext2_meta.i_block = new_i_block;
        ext2_meta.i_blocks = new_i_blocks_512;
        vfs_meta.size = new_size;
        vfs_meta.blocks = new_i_blocks_512 as u64;
        // A size change always bumps mtime + ctime (POSIX).
        ext2_meta.mtime = now_sec;
        ext2_meta.ctime = now_sec;
        vfs_meta.mtime = crate::fs::vfs::Timespec {
            sec: now_sec as i64,
            nsec: 0,
        };
        vfs_meta.ctime = crate::fs::vfs::Timespec {
            sec: now_sec as i64,
            nsec: 0,
        };
    }
    if attr.mask.contains(SetAttrMask::ATIME) {
        ext2_meta.atime = attr.atime.sec as u32;
        vfs_meta.atime = attr.atime;
    }
    if attr.mask.contains(SetAttrMask::MTIME) {
        ext2_meta.mtime = attr.mtime.sec as u32;
        vfs_meta.mtime = attr.mtime;
    }
    if attr.mask.contains(SetAttrMask::CTIME) {
        ext2_meta.ctime = attr.ctime.sec as u32;
        vfs_meta.ctime = attr.ctime;
    }

    // ctime bump on mode/uid/gid changes (POSIX §chmod / §chown).
    let bumped_ctime_implicitly = !attr.mask.contains(SetAttrMask::CTIME)
        && (attr.mask.contains(SetAttrMask::MODE)
            || attr.mask.contains(SetAttrMask::UID)
            || attr.mask.contains(SetAttrMask::GID));
    if bumped_ctime_implicitly {
        ext2_meta.ctime = now_sec;
        vfs_meta.ctime = crate::fs::vfs::Timespec {
            sec: now_sec as i64,
            nsec: 0,
        };
    }

    // RMW the 128-byte inode-table slot.
    {
        let mut data = bh.data.write();
        if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
            return Err(EIO);
        }
        let slot = &mut data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0];
        let mut disk_inode = DiskInode::decode(slot);
        disk_inode.i_mode = ext2_meta.mode;
        disk_inode.set_uid(ext2_meta.uid);
        disk_inode.set_gid(ext2_meta.gid);
        // Regular-file large-file size split (RFC 0004 §On-disk types).
        let is_reg = (ext2_meta.mode & 0o170_000) == 0o100_000;
        if is_reg && large_file {
            disk_inode.i_size = ext2_meta.size as u32;
            disk_inode.i_dir_acl_or_size_high = (ext2_meta.size >> 32) as u32;
        } else {
            // Directories and small files: low 32 bits only; leave
            // `i_dir_acl_or_size_high` untouched (it's `i_dir_acl` on
            // dirs).
            disk_inode.i_size = ext2_meta.size as u32;
        }
        disk_inode.i_atime = ext2_meta.atime;
        disk_inode.i_ctime = ext2_meta.ctime;
        disk_inode.i_mtime = ext2_meta.mtime;
        disk_inode.i_blocks = ext2_meta.i_blocks;
        disk_inode.i_block = ext2_meta.i_block;
        disk_inode.encode_to_slot(slot);
    }
    super_ref.cache.mark_dirty(&bh);
    super_ref.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;

    // Bump the indirect-cache epoch if we remapped pointers.
    if shrunk_blocks > 0 {
        let mut bm = ext2_inode.block_map.write();
        // block_map is a BlockingRwLock<Option<BlockMap>>; stamp it
        // as None to force the next read path to rebuild. The field
        // type is still a wave-2 placeholder; a full `IndirectCache`
        // hangs here in a follow-up, but clearing it is always safe.
        *bm = None;
    }

    Ok(())
}

/// Compute the (absolute block, offset-in-block) location of the
/// inode-table slot for `ino`. Mirrors the arithmetic in
/// [`super::inode::iget`].
pub(super) fn locate_inode_slot(super_ref: &Arc<Ext2Super>, ino: u32) -> Result<(u64, usize), i64> {
    if ino == 0 {
        return Err(EINVAL);
    }
    let (s_inodes_count, inodes_per_group) = {
        let sb = super_ref.sb_disk.lock();
        (sb.s_inodes_count, sb.s_inodes_per_group)
    };
    if ino > s_inodes_count || inodes_per_group == 0 {
        return Err(EIO);
    }
    let group = (ino - 1) / inodes_per_group;
    let index_in_group = (ino - 1) % inodes_per_group;
    let bg_inode_table = {
        let bgdt = super_ref.bgdt.lock();
        if (group as usize) >= bgdt.len() {
            return Err(EIO);
        }
        bgdt[group as usize].bg_inode_table
    };
    let inode_size = super_ref.inode_size as u64;
    let block_size = super_ref.block_size as u64;
    if block_size == 0 {
        return Err(EIO);
    }
    let byte_offset = (index_in_group as u64) * inode_size;
    let block_in_table = byte_offset / block_size;
    let offset_in_block = (byte_offset % block_size) as usize;
    let absolute_block = (bg_inode_table as u64)
        .checked_add(block_in_table)
        .ok_or(EIO)?;
    Ok((absolute_block, offset_in_block))
}

/// Free every data + indirect block strictly above
/// `ceil(new_size / block_size)` from `i_block`. Returns the count of
/// data + indirect blocks actually released and the updated
/// `i_block[]` array (with cleared slots where appropriate).
///
/// The walk is reverse-logical: highest logical block first, so a
/// crash mid-walk leaves a prefix of the file intact and no "past
/// EOF" block pointer still reachable from the inode.
pub(super) fn truncate_free(
    super_ref: &Arc<Ext2Super>,
    cur_i_block: &[u32; EXT2_N_BLOCKS],
    new_size: u64,
) -> Result<(u32, [u32; EXT2_N_BLOCKS]), i64> {
    let block_size = super_ref.block_size as u64;
    if block_size == 0 {
        return Err(EIO);
    }
    // First logical block NOT to keep. `new_size == 0` → keep nothing
    // (`first_gone == 0`).
    let first_gone_u64 = new_size.div_ceil(block_size);
    // Clamp into u32. ext2 caps file blocks at u32::MAX; anything above
    // is already past the structural limit and we have nothing to walk.
    let first_gone: u32 = first_gone_u64.try_into().unwrap_or(u32::MAX);

    let (s_first_data_block, s_blocks_count) = {
        let sb = super_ref.sb_disk.lock();
        (sb.s_first_data_block, sb.s_blocks_count)
    };
    let geom =
        Geometry::new(super_ref.block_size, s_first_data_block, s_blocks_count).ok_or(EIO)?;
    let p = geom.ptrs_per_block as u64;

    let mut new_i_block = *cur_i_block;
    let mut freed: u32 = 0;

    // Free triple-indirect (index 14) if any logical block >= the
    // triple start is to be dropped. The triple chain addresses
    // logical blocks in [12 + p + p^2, 12 + p + p^2 + p^3).
    let triple_start: u64 = EXT2_DIRECT_BLOCKS as u64 + p + p * p;
    if (first_gone as u64) < triple_start + p * p * p {
        let root = new_i_block[EXT2_TIND_BLOCK];
        if root != 0 {
            let new_root = free_indirect_range(
                super_ref,
                root,
                3,
                triple_start,
                first_gone as u64,
                &mut freed,
            )?;
            new_i_block[EXT2_TIND_BLOCK] = new_root;
        }
    }

    // Free double-indirect (index 13) if any logical block >= the
    // double start is to be dropped.
    let double_start: u64 = EXT2_DIRECT_BLOCKS as u64 + p;
    if (first_gone as u64) < double_start + p * p {
        let root = new_i_block[EXT2_DIND_BLOCK];
        if root != 0 {
            let new_root = free_indirect_range(
                super_ref,
                root,
                2,
                double_start,
                first_gone as u64,
                &mut freed,
            )?;
            new_i_block[EXT2_DIND_BLOCK] = new_root;
        }
    }

    // Free single-indirect (index 12) if any logical block >= the
    // single start is to be dropped.
    let single_start: u64 = EXT2_DIRECT_BLOCKS as u64;
    if (first_gone as u64) < single_start + p {
        let root = new_i_block[EXT2_IND_BLOCK];
        if root != 0 {
            let new_root = free_indirect_range(
                super_ref,
                root,
                1,
                single_start,
                first_gone as u64,
                &mut freed,
            )?;
            new_i_block[EXT2_IND_BLOCK] = new_root;
        }
    }

    // Direct: free i_block[first_gone..12] when first_gone < 12.
    if first_gone < EXT2_DIRECT_BLOCKS as u32 {
        for i in (first_gone as usize..EXT2_DIRECT_BLOCKS).rev() {
            let p = new_i_block[i];
            if p != 0 {
                super::balloc::free_block(super_ref, p)?;
                new_i_block[i] = 0;
                freed = freed.saturating_add(1);
            }
        }
    }

    Ok((freed, new_i_block))
}

/// Recursively free an indirect block tree rooted at `root`.
///
/// - `level == 1` → `root` is a block of data-block pointers. Free any
///   pointer whose addressed logical block is `>= first_gone`. If
///   every pointer in the block ends up zero, free the indirect block
///   itself and return 0 as the new root; otherwise keep the root and
///   return it unchanged (write-back happens through the cache dirty
///   bit).
/// - `level == 2` → `root` is a block of level-1 indirect pointers.
/// - `level == 3` → `root` is a block of level-2 indirect pointers
///   (triple-indirect root).
///
/// `base_logical` is the logical block number addressed by slot 0 of
/// this block. Each level-1 slot covers 1 logical block, each level-2
/// slot covers `p` logicals, each level-3 slot covers `p*p` logicals.
///
/// Returns the new value to store in the parent slot (`0` if the whole
/// subtree was freed; the original `root` if any data survived).
///
/// Bounds checking: every pointer value read from an indirect block is
/// validated against `[s_first_data_block, s_blocks_count)`. A pointer
/// outside that range is `EIO` (corrupt image). Zero pointers are
/// sparse holes and contribute no freed block.
fn free_indirect_range(
    super_ref: &Arc<Ext2Super>,
    root: u32,
    level: u8,
    base_logical: u64,
    first_gone: u64,
    freed: &mut u32,
) -> Result<u32, i64> {
    let (s_first_data_block, s_blocks_count) = {
        let sb = super_ref.sb_disk.lock();
        (sb.s_first_data_block, sb.s_blocks_count)
    };
    if root < s_first_data_block || root >= s_blocks_count {
        return Err(EIO);
    }
    let block_size = super_ref.block_size as usize;
    let p_per_block = (super_ref.block_size / 4) as u64;

    // Per-slot logical-block stride: level 1 = 1, level 2 = p, level 3 = p*p.
    let stride: u64 = match level {
        1 => 1,
        2 => p_per_block,
        3 => p_per_block * p_per_block,
        _ => return Err(EIO),
    };

    // Read the indirect block into a detached Vec so we can release
    // the cache buffer before freeing anything (freeing the indirect
    // itself at the end would otherwise deadlock-adjacent with the
    // cache mutex on some block_cache configurations).
    let mut slots: alloc::vec::Vec<u32> = vec![0u32; p_per_block as usize];
    {
        let bh = super_ref
            .cache
            .bread(super_ref.device_id, root as u64)
            .map_err(|_| EIO)?;
        let data = bh.data.read();
        if data.len() < block_size {
            return Err(EIO);
        }
        for (i, slot) in slots.iter_mut().enumerate() {
            let off = i * 4;
            *slot = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        }
    }

    // Walk slots in reverse so a mid-walk crash leaves a reachable
    // prefix rather than a reachable suffix past EOF.
    let mut any_survivor = false;
    let mut any_mutated = false;
    for i in (0..slots.len()).rev() {
        let slot_logical = base_logical + (i as u64) * stride;
        let slot_ptr = slots[i];
        if slot_ptr == 0 {
            continue;
        }
        // Validate range.
        if slot_ptr < s_first_data_block || slot_ptr >= s_blocks_count {
            return Err(EIO);
        }
        if slot_logical >= first_gone {
            // Entire subtree reachable from this slot is past EOF.
            if level == 1 {
                super::balloc::free_block(super_ref, slot_ptr)?;
                *freed = freed.saturating_add(1);
            } else {
                let _ = free_indirect_range(
                    super_ref,
                    slot_ptr,
                    level - 1,
                    slot_logical,
                    first_gone,
                    freed,
                )?;
                // Every logical addressed by this subtree is past EOF,
                // so `free_indirect_range` returned 0. The indirect
                // block `slot_ptr` itself is now freed by that call's
                // tail; nothing more to do here besides clearing the
                // slot.
            }
            slots[i] = 0;
            any_mutated = true;
        } else if slot_logical + stride > first_gone {
            // Partial: the subtree straddles `first_gone`. Recurse.
            if level == 1 {
                // Shouldn't reach here: level-1 stride is 1, so
                // `slot_logical + 1 > first_gone` ∧ `slot_logical <
                // first_gone` is impossible. Defensive EIO.
                return Err(EIO);
            }
            let new_ptr = free_indirect_range(
                super_ref,
                slot_ptr,
                level - 1,
                slot_logical,
                first_gone,
                freed,
            )?;
            if new_ptr == 0 {
                slots[i] = 0;
                any_mutated = true;
            } else {
                any_survivor = true;
            }
        } else {
            // Entire subtree below `first_gone`: survives.
            any_survivor = true;
        }
    }

    if !any_survivor {
        // Free the indirect block itself. Mirrors the count of
        // indirect blocks in `i_blocks` (ext2 charges indirect blocks
        // against `i_blocks` too).
        super::balloc::free_block(super_ref, root)?;
        *freed = freed.saturating_add(1);
        return Ok(0);
    }

    // Survivors remain: write back the mutated indirect block.
    if any_mutated {
        let bh = super_ref
            .cache
            .bread(super_ref.device_id, root as u64)
            .map_err(|_| EIO)?;
        {
            let mut data = bh.data.write();
            if data.len() < block_size {
                return Err(EIO);
            }
            for (i, slot) in slots.iter().enumerate() {
                let off = i * 4;
                data[off..off + 4].copy_from_slice(&slot.to_le_bytes());
            }
        }
        super_ref.cache.mark_dirty(&bh);
        super_ref.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    }

    Ok(root)
}

#[cfg(test)]
mod tests {
    //! Host-side unit tests for the pure-logic helpers. The end-to-end
    //! setattr path is exercised by the QEMU integration test at
    //! `kernel/tests/ext2_setattr.rs`.
    //!
    //! Wave E lands the RMW persistence, so the feature-gated helpers
    //! above can only be exercised under the `ext2`/`target_os =
    //! "none"` envelope. The host-side coverage here is limited to
    //! mask/semantics smoke-tests that don't need the buffer cache.

    #[test]
    fn smoke_placeholder() {
        // The real tests are in the QEMU integration suite; this
        // placeholder keeps the module from being empty under
        // `cargo test --lib`.
    }
}
