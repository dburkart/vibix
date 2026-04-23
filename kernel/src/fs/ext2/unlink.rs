//! ext2 unlink / rmdir — `InodeOps::unlink` + `InodeOps::rmdir` (issue #569).
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Unlink
//! semantics and §Orphan list are the normative specs. Workstream E.
//!
//! # What this wave does
//!
//! 1. **Remove the dirent** in the parent directory — extend the
//!    previous live record's `rec_len` to swallow the target's slot
//!    (or, when the target is the first live record in its block,
//!    zero its `inode` field and turn it into a tombstone). The
//!    parent's data block is marked dirty and synced.
//! 2. **Decrement the child's `i_links_count`** and update `i_ctime`.
//!    For `rmdir` the child loses both its `.` self-link and its
//!    parent's `..` back-link, so `i_links_count` goes from 2 → 0; the
//!    parent's own `i_links_count` loses one for the `..` back-link.
//! 3. **If `i_links_count` hits zero**, push the child onto the on-
//!    disk orphan list (`s_last_orphan`) and pin an `Arc<Inode>` in
//!    [`super::inode::OrphanList`]. The pin keeps the inode resident
//!    until the last open fd drops (handled by #573's final-close
//!    sequence); this PR guarantees the add-on-hit-zero half of the
//!    invariant. The child's on-disk `i_dtime` is repurposed as the
//!    orphan-chain next-pointer (RFC 0004 §Orphan list).
//!
//! # What this wave does *not* wire
//!
//! - Actual block / inode freeing: that's #573's final-close path.
//!   `balloc::free_block` / `ialloc::free_inode` are available but not
//!   called here — an orphaned inode's blocks stay reserved until
//!   close-with-links-zero kicks the drain.
//! - Sticky bit (`S_ISVTX`) + owner permission checks: the
//!   `InodeOps::unlink` trait signature doesn't yet thread a
//!   `Credential`; the generic VFS layer (`sys_unlinkat`) runs
//!   `MAY_WRITE | MAY_EXEC` against the parent before calling us, and
//!   the sticky-bit owner check is filed as a follow-up once the
//!   trait grows a `cred` arg (see RFC 0004 §Unlink semantics).
//! - Renames against an unlinked-but-open inode: that's the rename
//!   issue; this path only handles the linked→unlinked transition.

use alloc::sync::Arc;

use super::dir::{filetype_valid_from_incompat, DirEntryIter};
use super::disk::{
    Ext2DirEntry2, Ext2Inode as DiskInode, Ext2SuperBlock, EXT2_DIR_REC_HEADER_LEN,
    EXT2_INODE_SIZE_V0, EXT2_SUPERBLOCK_SIZE,
};
use super::file::build_metadata_map;
use super::fs::{Ext2MountFlags, Ext2Super, SUPERBLOCK_BYTE_OFFSET};
use super::indirect::{resolve_block, Geometry, WalkError};
use super::inode::{iget, Ext2Inode};

use crate::fs::vfs::inode::{Inode, InodeKind};
use crate::fs::vfs::super_block::SuperBlock;
use crate::fs::{EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY, EROFS};

use core::sync::atomic::Ordering;

/// Outcome of [`locate_dirent`]: the absolute block holding the live
/// record, the byte offset inside that block where the record starts,
/// the byte offset of the **previous** live record (or `None` if the
/// target is first-in-block), the target record's `rec_len`, and the
/// target's ino + file_type.
#[derive(Debug, Clone, Copy)]
pub(super) struct DirentLocation {
    pub(super) abs_block: u32,
    pub(super) offset_in_block: usize,
    pub(super) prev_offset_in_block: Option<usize>,
    pub(super) rec_len: usize,
    pub(super) child_ino: u32,
    #[allow(dead_code)]
    pub(super) file_type: u8,
}

/// Walk `dir`'s data blocks until `name` is found, returning the exact
/// on-disk location of its record. Used by both `unlink` and `rmdir`
/// to locate the dirent they're about to remove.
///
/// Returns `ENOENT` if the name isn't present.
pub(super) fn locate_dirent(
    super_: &Arc<Ext2Super>,
    dir: &Ext2Inode,
    name: &[u8],
) -> Result<DirentLocation, i64> {
    if name.is_empty() || name == b"." || name == b".." {
        return Err(EINVAL);
    }
    let block_size = super_.block_size;
    let (s_first_data_block, s_blocks_count, s_feature_incompat) = {
        let sb = super_.sb_disk.lock();
        (
            sb.s_first_data_block,
            sb.s_blocks_count,
            sb.s_feature_incompat,
        )
    };
    let geom = Geometry::new(block_size, s_first_data_block, s_blocks_count).ok_or(EIO)?;
    let md = build_metadata_map(super_);
    let filetype_valid = filetype_valid_from_incompat(s_feature_incompat);

    let meta = dir.meta.read();
    let size = meta.size;
    let i_block = meta.i_block;
    drop(meta);

    let block_count = size.div_ceil(block_size as u64);
    for logical in 0..block_count {
        let logical_off = logical * block_size as u64;
        let logical_len =
            core::cmp::min(size.saturating_sub(logical_off), block_size as u64) as usize;
        let logical_u32: u32 = logical.try_into().map_err(|_| EIO)?;
        let abs = match resolve_block(
            &super_.cache,
            super_.device_id,
            &geom,
            &md,
            &i_block,
            logical_u32,
            None,
        ) {
            Ok(Some(a)) => a,
            Ok(None) => return Err(EIO),
            Err(WalkError::Io) | Err(WalkError::Corrupt) => return Err(EIO),
        };

        let bh = super_
            .cache
            .bread(super_.device_id, abs as u64)
            .map_err(|_| EIO)?;
        let data = bh.data.read();
        let end = core::cmp::min(data.len(), logical_len);

        // Scan forward tracking the running cursor + the offset of
        // the previous *live* (non-tombstone) record. We can't use
        // DirEntryIter directly because it hides both tombstones and
        // the per-record offsets; we roll a minimal parallel walker.
        let mut cursor = 0usize;
        let mut prev_live: Option<usize> = None;
        while cursor < end {
            if end - cursor < EXT2_DIR_REC_HEADER_LEN {
                break;
            }
            let hdr = Ext2DirEntry2::decode_header(&data[cursor..cursor + EXT2_DIR_REC_HEADER_LEN]);
            let rec_len = hdr.rec_len as usize;
            if rec_len < EXT2_DIR_REC_HEADER_LEN || rec_len % 4 != 0 || cursor + rec_len > end {
                return Err(EIO);
            }
            if hdr.inode != 0 {
                let name_len = hdr.name_len as usize;
                let name_start = cursor + EXT2_DIR_REC_HEADER_LEN;
                let name_end = name_start + name_len;
                if name_end > cursor + rec_len {
                    return Err(EIO);
                }
                if &data[name_start..name_end] == name {
                    let file_type = if filetype_valid { hdr.file_type } else { 0 };
                    return Ok(DirentLocation {
                        abs_block: abs,
                        offset_in_block: cursor,
                        prev_offset_in_block: prev_live,
                        rec_len,
                        child_ino: hdr.inode,
                        file_type,
                    });
                }
                prev_live = Some(cursor);
            }
            cursor += rec_len;
        }
    }
    Err(ENOENT)
}

/// Is `dir`'s content limited to `.` and `..`? Walks every allocated
/// block: ext2 directories don't shrink when names are removed, so a
/// formerly-full directory can have multiple allocated blocks with
/// only `.` / `..` still live. A single non-`.`/`..` live record
/// anywhere in the walk proves the directory is non-empty.
pub(super) fn dir_is_empty(super_: &Arc<Ext2Super>, dir: &Ext2Inode) -> Result<bool, i64> {
    let block_size = super_.block_size;
    let (s_first_data_block, s_blocks_count, s_feature_incompat) = {
        let sb = super_.sb_disk.lock();
        (
            sb.s_first_data_block,
            sb.s_blocks_count,
            sb.s_feature_incompat,
        )
    };
    let geom = Geometry::new(block_size, s_first_data_block, s_blocks_count).ok_or(EIO)?;
    let md = build_metadata_map(super_);
    let filetype_valid = filetype_valid_from_incompat(s_feature_incompat);

    let meta = dir.meta.read();
    let size = meta.size;
    let i_block = meta.i_block;
    drop(meta);

    let block_count = size.div_ceil(block_size as u64);
    for logical in 0..block_count {
        let logical_off = logical * block_size as u64;
        let logical_len =
            core::cmp::min(size.saturating_sub(logical_off), block_size as u64) as usize;
        let logical_u32: u32 = logical.try_into().map_err(|_| EIO)?;
        let abs = match resolve_block(
            &super_.cache,
            super_.device_id,
            &geom,
            &md,
            &i_block,
            logical_u32,
            None,
        ) {
            Ok(Some(a)) => a,
            Ok(None) => return Err(EIO),
            Err(_) => return Err(EIO),
        };
        let bh = super_
            .cache
            .bread(super_.device_id, abs as u64)
            .map_err(|_| EIO)?;
        let data = bh.data.read();
        let end = core::cmp::min(data.len(), logical_len);
        for rec in DirEntryIter::new(&data[..end], filetype_valid) {
            let view = rec.map_err(|_| EIO)?;
            if view.name != b"." && view.name != b".." {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Remove the record at `loc` from its parent directory block. Either
/// extends the previous live record's `rec_len` to swallow the target,
/// or (if the target is first-in-block) turns it into a tombstone by
/// zeroing the `inode` field. The block is marked dirty and synced
/// before returning.
pub(super) fn remove_dirent_at(super_: &Arc<Ext2Super>, loc: &DirentLocation) -> Result<(), i64> {
    let bh = super_
        .cache
        .bread(super_.device_id, loc.abs_block as u64)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        match loc.prev_offset_in_block {
            Some(prev) => {
                // Extend prev.rec_len by target's rec_len so the walker
                // skips straight past the removed slot. The payload
                // bytes at `loc.offset_in_block..` are now dead slack,
                // which is the canonical ext2 "deleted name" state.
                let prev_slot = &data[prev..prev + EXT2_DIR_REC_HEADER_LEN];
                let mut hdr = Ext2DirEntry2::decode_header(prev_slot);
                let new_len = (hdr.rec_len as usize).checked_add(loc.rec_len).ok_or(EIO)?;
                if new_len > u16::MAX as usize {
                    return Err(EIO);
                }
                hdr.rec_len = new_len as u16;
                hdr.encode_header_to_slot(&mut data[prev..prev + EXT2_DIR_REC_HEADER_LEN]);
            }
            None => {
                // First live record in the block. The walker requires
                // the block to start with *some* header (otherwise it
                // tries to decode the very first bytes as one), so we
                // can't collapse the record — we must tombstone it by
                // zeroing the `inode` field, preserving `rec_len` so
                // the walk skips past intact.
                let slot = &mut data[loc.offset_in_block..loc.offset_in_block + 4];
                slot.copy_from_slice(&0u32.to_le_bytes());
            }
        }
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Read the raw 128-byte rev-0 prefix for `ino` into a [`DiskInode`].
/// Mirrors [`super::orphan::read_disk_inode`] (private there) so the
/// unlink path doesn't need to reach across module boundaries.
fn read_disk_inode(super_: &Arc<Ext2Super>, ino: u32) -> Result<(DiskInode, u64, usize), i64> {
    let (s_inodes_count, s_inodes_per_group) = {
        let sb = super_.sb_disk.lock();
        (sb.s_inodes_count, sb.s_inodes_per_group)
    };
    if ino == 0 || ino > s_inodes_count {
        return Err(EINVAL);
    }
    if s_inodes_per_group == 0 {
        return Err(EIO);
    }
    let group = (ino - 1) / s_inodes_per_group;
    let index_in_group = (ino - 1) % s_inodes_per_group;
    let bg_inode_table = {
        let bgdt = super_.bgdt.lock();
        if (group as usize) >= bgdt.len() {
            return Err(EIO);
        }
        bgdt[group as usize].bg_inode_table
    };
    let inode_size = super_.inode_size as u64;
    let block_size = super_.block_size as u64;
    let byte_offset = (index_in_group as u64) * inode_size;
    let block_in_table = byte_offset / block_size;
    let offset_in_block = (byte_offset % block_size) as usize;
    let absolute_block = (bg_inode_table as u64)
        .checked_add(block_in_table)
        .ok_or(EIO)?;
    let bh = super_
        .cache
        .bread(super_.device_id, absolute_block)
        .map_err(|_| EIO)?;
    let data = bh.data.read();
    if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
        return Err(EIO);
    }
    let mut slot = [0u8; EXT2_INODE_SIZE_V0];
    slot.copy_from_slice(&data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0]);
    Ok((DiskInode::decode(&slot), absolute_block, offset_in_block))
}

/// RMW an on-disk inode slot with `writer` and sync the block.
pub(super) fn rmw_disk_inode<F>(super_: &Arc<Ext2Super>, ino: u32, writer: F) -> Result<(), i64>
where
    F: FnOnce(&mut DiskInode),
{
    let (mut disk, absolute_block, offset_in_block) = read_disk_inode(super_, ino)?;
    writer(&mut disk);
    let bh = super_
        .cache
        .bread(super_.device_id, absolute_block)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
            return Err(EIO);
        }
        disk.encode_to_slot(&mut data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0]);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Flush the in-memory `sb_disk` snapshot back to its on-disk slot.
/// Mirrors `ialloc::flush_superblock`; kept as a second copy rather
/// than exported so each mutator module owns its flush boundary.
fn flush_superblock(super_: &Arc<Ext2Super>, sb: &Ext2SuperBlock) -> Result<(), i64> {
    let block_size = super_.block_size as u64;
    if block_size == 0 {
        return Err(EIO);
    }
    let sb_block = SUPERBLOCK_BYTE_OFFSET / block_size;
    let sb_offset_in_block = (SUPERBLOCK_BYTE_OFFSET % block_size) as usize;

    let bh = super_
        .cache
        .bread(super_.device_id, sb_block)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        if sb_offset_in_block + EXT2_SUPERBLOCK_SIZE > data.len() {
            return Err(EIO);
        }
        sb.encode_to_slot(&mut data[sb_offset_in_block..sb_offset_in_block + EXT2_SUPERBLOCK_SIZE]);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Decrement `bg_used_dirs_count` on the BGDT entry for the group that
/// owns `ino`. Called from `rmdir` when a directory inode has its link
/// count driven to zero.
fn decrement_used_dirs(super_: &Arc<Ext2Super>, ino: u32) -> Result<(), i64> {
    use super::disk::EXT2_GROUP_DESC_SIZE;
    let (s_inodes_per_group, s_first_data_block) = {
        let sb = super_.sb_disk.lock();
        (sb.s_inodes_per_group, sb.s_first_data_block)
    };
    if s_inodes_per_group == 0 {
        return Err(EIO);
    }
    let group = (ino - 1) / s_inodes_per_group;
    let block_size = super_.block_size;
    let entries_per_block = block_size / EXT2_GROUP_DESC_SIZE as u32;
    if entries_per_block == 0 {
        return Err(EIO);
    }
    let block_off = group / entries_per_block;
    let index_in_block = (group % entries_per_block) as usize;
    let bgdt_blk = (s_first_data_block as u64)
        .checked_add(1)
        .and_then(|v| v.checked_add(block_off as u64))
        .ok_or(EIO)?;

    // Update the in-memory mirror first, then RMW-flush the on-disk
    // slot. Both must agree or a follow-up allocator pass will
    // overcount dirs.
    let encoded_slot = {
        let mut bgdt = super_.bgdt.lock();
        let group_idx = group as usize;
        if group_idx >= bgdt.len() {
            return Err(EIO);
        }
        let bg = &mut bgdt[group_idx];
        bg.bg_used_dirs_count = bg.bg_used_dirs_count.saturating_sub(1);
        let mut slot = [0u8; EXT2_GROUP_DESC_SIZE];
        bg.encode_to_slot(&mut slot);
        slot
    };

    let bh = super_
        .cache
        .bread(super_.device_id, bgdt_blk)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        let byte_off = index_in_block * EXT2_GROUP_DESC_SIZE;
        if byte_off + EXT2_GROUP_DESC_SIZE > data.len() {
            return Err(EIO);
        }
        data[byte_off..byte_off + EXT2_GROUP_DESC_SIZE].copy_from_slice(&encoded_slot);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Push `child` onto the on-disk orphan list: stamp its `i_dtime` with
/// the current `s_last_orphan`, then update the superblock's
/// `s_last_orphan` to `child.ino`. The in-memory
/// [`super::inode::OrphanList`] also takes a strong `Arc<Inode>` ref
/// so the inode stays resident until the final-close path (#573)
/// frees its blocks.
///
/// Caller contract: `child.meta.links_count == 0`, the child's
/// `unlinked` atomic has already been set to `true`, and the on-disk
/// `i_links_count` has been flushed.
pub(super) fn push_on_orphan_list(
    super_: &Arc<Ext2Super>,
    child_ino: u32,
    child_inode: &Arc<Inode>,
) -> Result<(), i64> {
    // 1. Capture current head, then replace it with child_ino. Serialize
    //    against a concurrent orphan push via the alloc_mutex — this
    //    isn't strictly an allocation, but `s_last_orphan` is a
    //    superblock-wide list head and we want the same serialization
    //    point as balloc/ialloc use for their sb writes.
    let _guard = super_.alloc_mutex.lock();

    let old_head = {
        let mut sb = super_.sb_disk.lock();
        let old = sb.s_last_orphan;
        sb.s_last_orphan = child_ino;
        flush_superblock(super_, &sb)?;
        old
    };

    // 2. Stamp the child's on-disk i_dtime with the old head. The
    //    mount-time orphan-chain validator (#564) reads this field as
    //    the next-pointer while i_links_count == 0.
    rmw_disk_inode(super_, child_ino, |disk| {
        disk.i_dtime = old_head;
    })?;

    // 3. Pin an Arc<Inode> in the in-memory orphan list. Use the
    //    caller-supplied Inode Arc; this is the same object the VFS
    //    holds through any still-open fd, so the refcount-based
    //    "last close" detection (#573) will work directly against it.
    super_
        .orphan_list
        .lock()
        .entry(child_ino)
        .or_insert_with(|| child_inode.clone());

    Ok(())
}

/// Current wall-clock seconds for stamping `i_ctime`. Routes through
/// [`crate::fs::vfs::Timespec::now`] — the same source `utimensat
/// UTIME_NOW` uses. Ext2 timestamps are second-granularity on rev-0;
/// the nsec is dropped here.
#[inline]
pub(super) fn now_secs() -> u32 {
    crate::fs::vfs::Timespec::now().sec as u32
}

/// Core unlink/rmdir shared body. `expect_dir` is:
///
/// - `Some(false)` — `unlink(2)` semantics. Target must not be a
///   directory (`EISDIR` if it is).
/// - `Some(true)` — `rmdir(2)` semantics. Target must be a directory
///   (`ENOTDIR` if not) and must be empty (`ENOTEMPTY` otherwise).
///
/// The caller has already permission-checked the parent via the
/// generic VFS layer. RO mount is refused with `EROFS`.
fn unlink_common(
    parent_dir: &Ext2Inode,
    parent_vfs: &Inode,
    name: &[u8],
    expect_dir: bool,
) -> Result<(), i64> {
    let super_ = parent_dir.super_ref.upgrade().ok_or(EIO)?;
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    // 1. Locate the dirent. locate_dirent rejects "." / ".." up front.
    let loc = locate_dirent(&super_, parent_dir, name)?;

    // 2. Load the child inode through the standard cache path so the
    //    VFS sees the same Arc<Inode> any open-fd holder has. We need
    //    an Arc<SuperBlock> for iget; reach it through the parent's
    //    weak-ref chain. If the parent's sb weak doesn't upgrade we're
    //    mid-teardown and should bail with EIO.
    let parent_sb = {
        // The Ext2Inode doesn't carry a Weak<SuperBlock> directly, but
        // the Arc<Ext2Super> is reachable via super_ref; Ext2Super
        // doesn't hold the VFS SuperBlock either, so we resolve
        // through the mount table.
        resolve_sb_for_super(&super_)?
    };
    let child_arc = iget(&super_, &parent_sb, loc.child_ino)?;

    // 3. Kind guard.
    match (expect_dir, child_arc.kind) {
        (false, InodeKind::Dir) => return Err(EISDIR),
        (true, k) if k != InodeKind::Dir => return Err(ENOTDIR),
        _ => {}
    }

    // 4. For rmdir, require empty. Pull the concrete Ext2Inode through
    //    the same cache lookup — inode_cache keeps it alive as long as
    //    child_arc is.
    let child_ext2 = ext2_inode_from_vfs(&super_, &child_arc).ok_or(EIO)?;
    if expect_dir && !dir_is_empty(&super_, &child_ext2)? {
        return Err(ENOTEMPTY);
    }

    // 5. Remove the dirent from the parent block.
    remove_dirent_at(&super_, &loc)?;

    // 6. Update the child (and, for rmdir, the parent) link counts.
    //    For rmdir: links goes 2 → 0 on a normal empty dir (the ".."
    //    self-loop counts plus the parent's back-link); for unlink:
    //    links goes 1 → 0 on the common case. We compute the new
    //    count from the on-disk current value to stay correct under
    //    concurrent hard-link adds (when link/rename lands).
    let now = now_secs();
    let mut new_links: u16 = 0;
    rmw_disk_inode(&super_, loc.child_ino, |disk| {
        let dec = if expect_dir { 2u16 } else { 1u16 };
        disk.i_links_count = disk.i_links_count.saturating_sub(dec);
        disk.i_ctime = now;
        new_links = disk.i_links_count;
    })?;

    // Sync the in-memory Ext2InodeMeta mirror so a still-open fd sees
    // the updated link count via getattr without a fresh iget.
    {
        let mut meta = child_ext2.meta.write();
        let dec = if expect_dir { 2u16 } else { 1u16 };
        meta.links_count = meta.links_count.saturating_sub(dec);
        meta.ctime = now;
    }
    // VFS-layer nlink mirror too.
    {
        let mut vfs_meta = child_arc.meta.write();
        let dec = if expect_dir { 2 } else { 1 };
        vfs_meta.nlink = vfs_meta.nlink.saturating_sub(dec);
        vfs_meta.ctime = crate::fs::vfs::Timespec {
            sec: now as i64,
            nsec: 0,
        };
    }

    // 7. rmdir-specific: decrement parent's links_count (loses ".."
    //    back-link) and the BGDT's bg_used_dirs_count for the child's
    //    group.
    if expect_dir {
        rmw_disk_inode(&super_, parent_dir.ino, |disk| {
            disk.i_links_count = disk.i_links_count.saturating_sub(1);
            disk.i_ctime = now;
        })?;
        {
            let mut meta = parent_dir.meta.write();
            meta.links_count = meta.links_count.saturating_sub(1);
            meta.ctime = now;
        }
        {
            let mut parent_vfs_meta = parent_vfs.meta.write();
            parent_vfs_meta.nlink = parent_vfs_meta.nlink.saturating_sub(1);
            parent_vfs_meta.ctime = crate::fs::vfs::Timespec {
                sec: now as i64,
                nsec: 0,
            };
        }
        decrement_used_dirs(&super_, loc.child_ino)?;
    }

    // 8. On hit-zero: mark unlinked, push on orphan list.
    if new_links == 0 {
        child_ext2.unlinked.store(true, Ordering::SeqCst);
        push_on_orphan_list(&super_, loc.child_ino, &child_arc)?;
    }

    Ok(())
}

/// Public entry point for `InodeOps::unlink`.
pub fn unlink(parent_dir: &Ext2Inode, parent_vfs: &Inode, name: &[u8]) -> Result<(), i64> {
    unlink_common(parent_dir, parent_vfs, name, /* expect_dir */ false)
}

/// Public entry point for `InodeOps::rmdir`.
pub fn rmdir(parent_dir: &Ext2Inode, parent_vfs: &Inode, name: &[u8]) -> Result<(), i64> {
    unlink_common(parent_dir, parent_vfs, name, /* expect_dir */ true)
}

/// Resolve the mounted `SuperBlock` for this `Ext2Super`. `iget`
/// requires a `&Arc<SuperBlock>`; the only path available from a live
/// `Ext2Super` is through the inode cache (any live child Arc<Inode>
/// pins the sb through its `Weak<SuperBlock>`). We ask the cache's
/// root-ino slot, which [`super::fs::Ext2Fs::mount`] pins before
/// returning.
pub(super) fn resolve_sb_for_super(super_: &Arc<Ext2Super>) -> Result<Arc<SuperBlock>, i64> {
    let cache = super_.inode_cache.lock();
    // Any cached entry will do; root is guaranteed cached at mount.
    for (_, weak) in cache.iter() {
        if let Some(inode) = weak.upgrade() {
            if let Some(sb) = inode.sb.upgrade() {
                return Ok(sb);
            }
        }
    }
    Err(EIO)
}

/// Look up the driver-private `Arc<Ext2Inode>` for a VFS `Inode` via
/// the parallel ext2 inode cache that [`super::inode::iget`] publishes.
/// Returns `None` only if the cache entry was evicted under us —
/// impossible on a well-formed call path because the caller always
/// holds a strong `Arc<Inode>` keeping the concrete `Arc<Ext2Inode>`
/// alive through `inode.ops`.
pub(super) fn ext2_inode_from_vfs(
    super_: &Arc<Ext2Super>,
    inode: &Arc<Inode>,
) -> Option<Arc<Ext2Inode>> {
    let cache = super_.ext2_inode_cache.lock();
    cache.get(&(inode.ino as u32)).and_then(|w| w.upgrade())
}

/// Rest of the name-lookup dirent scan used for testing: we don't
/// need the full walker here, but the test binary does. Re-export a
/// thin helper so integration tests can confirm tombstone state
/// without rebuilding the dirent parse themselves.
#[allow(dead_code)]
pub fn dirent_is_live(super_: &Arc<Ext2Super>, dir: &Ext2Inode, name: &[u8]) -> Result<bool, i64> {
    match locate_dirent(super_, dir, name) {
        Ok(_) => Ok(true),
        Err(e) if e == ENOENT => Ok(false),
        Err(e) => Err(e),
    }
}

// Host-side unit tests: the body of this module is all I/O against a
// `BlockCache`, so every meaningful assertion belongs under the QEMU
// integration harness. See `kernel/tests/ext2_unlink.rs`.
