//! ext2 `InodeOps::link` + `InodeOps::symlink` — hard-link and
//! symbolic-link creation on the write path.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Hard links,
//! §Symbolic links, §Fast symlink format. Workstream E, issue #570.
//!
//! # Hard link (`link`)
//!
//! A hard link is a second dirent pointing at an already-existing
//! inode. The on-disk change is:
//!
//! 1. Bump the **target** inode's `i_links_count` and rewrite its
//!    inode-table slot. Sync the slot block so a crash between step 1
//!    and step 2 leaves the inode with a slightly-inflated link count,
//!    which `e2fsck` trims back on next mount.
//! 2. Insert a new dirent in the parent directory block pointing at
//!    the target's ino with the correct `file_type` byte.
//!
//! POSIX (`link(2)`) forbids linking a directory — we always refuse
//! with `EPERM` regardless of credential (the traditional superuser
//! exception is an operational footgun that ext2's RFC explicitly
//! disables). Cross-superblock links return `EXDEV`.
//!
//! If the link count is already at its on-disk ceiling (`u16::MAX`) the
//! request fails with `EMLINK` — bumping would overflow and corrupt
//! the count.
//!
//! # Symbolic link (`symlink`)
//!
//! A symlink is a new inode whose body is the target path string.
//! The `i_mode` is `S_IFLNK | 0o777` (POSIX §4.10 mandates 0777 for
//! symlink permission bits — they're never consulted; the permission
//! check happens on the link's target during path resolution).
//!
//! Two on-disk shapes, picked by target length:
//!
//! - **Fast symlink** (target ≤ 60 bytes): the bytes live inline in
//!   `i_block[0..15]` (15 × 4 = 60 bytes). `i_blocks = 0`, no data
//!   block is allocated. The read path's gate in [`super::symlink`]
//!   keys off `is_symlink && i_blocks == 0 && i_size <= 60`.
//! - **Slow symlink** (target > 60 bytes, ≤ `PATH_MAX = 4095`): we
//!   allocate one data block via [`super::balloc::alloc_block`],
//!   write the target bytes into it, and stamp `i_block[0]` with the
//!   block number. `i_blocks = block_size / 512` (the single
//!   allocated block in 512-byte sectors).
//!
//! Write ordering mirrors [`super::create`]'s regular-file pipeline:
//! `alloc_inode` → (slow only: `alloc_block` + write target) → encode
//! inode + flush → insert dirent → flush. A crash at any step leaves
//! either an orphan inode (if the dirent never landed) or a valid
//! symlink — never a dangling dirent.
//!
//! # What this module does *not* do
//!
//! - `readlink` — covered by [`super::symlink`] (#563) on the read
//!   side.
//! - Permission checks. The generic VFS layer runs
//!   `permission(parent, MAY_WRITE | MAY_EXEC, cred)` before
//!   dispatching; we assume the caller has already done so.
//! - Credential-aware owner/group stamping. Like `create.rs`, the new
//!   inode's uid/gid are both `0` until the `Credential` threading
//!   from RFC 0004 §Credentials lands.

use alloc::sync::Arc;

use super::create::{add_link, read_inode_slot, validate_name, write_new_inode};
use super::disk::{Ext2Inode as DiskInode, EXT2_FT_SYMLINK, EXT2_N_BLOCKS};
use super::fs::{Ext2MountFlags, Ext2Super};
use super::ialloc::{alloc_inode, free_inode};
use super::inode::{iget, Ext2Inode};
use super::symlink::EXT2_FAST_SYMLINK_MAX;

use crate::fs::vfs::inode::{Inode, InodeKind};
use crate::fs::vfs::super_block::SuperBlock;
use crate::fs::vfs::Timespec;
use crate::fs::{EEXIST, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOTDIR, EPERM, EROFS};

/// `PATH_MAX` for symlink targets. POSIX caps a path at 4096 including
/// the trailing NUL; the stored-target length excludes the NUL, so a
/// symlink target may be up to 4095 bytes. Larger targets return
/// `ENAMETOOLONG`.
pub const EXT2_SYMLINK_TARGET_MAX: usize = 4095;

/// ext2 ceiling on `i_links_count`. The field is a `u16` on disk.
/// Hitting the ceiling makes further `link(2)` calls against the inode
/// return `EMLINK` (per POSIX). Ext3+ raises this via the
/// `DIR_NLINK` feature; ext2's cap is hard.
pub const EXT2_LINK_MAX: u16 = u16::MAX;

/// `link(2)` errno for "too many links". Defined here to keep the
/// link-specific errno gathered in one place — the kernel's canonical
/// errno table in `kernel/src/fs/mod.rs` doesn't yet re-export `EMLINK`
/// because no caller before this module needed it.
pub const EMLINK: i64 = -31;

// ---------------------------------------------------------------------------
// Hard link — InodeOps::link
// ---------------------------------------------------------------------------

/// Insert a new dirent `name` in `parent` that points at the existing
/// inode `target`. Bumps the target's `i_links_count` first, then
/// inserts the dirent. See the module docs for the full ordering story.
pub fn link(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    parent_vfs: &Inode,
    target: &Inode,
    name: &[u8],
) -> Result<(), i64> {
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }
    validate_name(name)?;
    if parent_vfs.kind != InodeKind::Dir {
        return Err(ENOTDIR);
    }
    // POSIX: link(2) against a directory is refused unconditionally on
    // this driver. Linux historically allowed it for root-with-
    // CAP_DAC_READ_SEARCH, but the RFC rules it out because a linked
    // directory breaks `..` invariant assumptions across the tree.
    if target.kind == InodeKind::Dir {
        return Err(EPERM);
    }

    // Cross-superblock links are a hard EXDEV. The VFS layer already
    // filters most of these at the `linkat` entry point but a
    // user-mode-driver test could call us directly; keep the check so
    // the driver alone is sufficient.
    let parent_sb = parent_vfs.sb.upgrade().ok_or(EIO)?;
    let target_sb = target.sb.upgrade().ok_or(EIO)?;
    if !Arc::ptr_eq(&parent_sb, &target_sb) {
        return Err(crate::fs::EXDEV);
    }

    // Serialise directory mutations on the parent, same as create_common.
    let _parent_guard = parent_vfs.dir_rwsem.write();

    // Refuse duplicate name up front; anything other than ENOENT
    // propagates.
    match super::dir::lookup(super_, parent, name) {
        Ok(_) => return Err(EEXIST),
        Err(e) if e == ENOENT => {}
        Err(e) => return Err(e),
    }

    let target_ino = target.ino as u32;
    if target_ino == 0 {
        return Err(EINVAL);
    }

    // Step 1: bump the target's i_links_count on disk (and detect
    // ceiling). Re-read through the buffer cache so any concurrent
    // setattr/unlink observation is coherent.
    let slot = read_inode_slot(super_, target_ino)?;
    let mut disk = DiskInode::decode(&slot);
    if disk.i_links_count == EXT2_LINK_MAX {
        return Err(EMLINK);
    }
    // Also guard against the inode having hit `i_dtime != 0` (tombstone
    // — on the orphan list awaiting final-close reclaim). Linking into
    // such an inode would revive a half-freed object.
    if disk.i_dtime != 0 {
        return Err(ENOENT);
    }
    disk.i_links_count = disk.i_links_count.saturating_add(1);
    // Touch i_ctime — POSIX mandates that link(2) updates ctime on the
    // target inode.
    let now = Timespec::now().sec as u32;
    disk.i_ctime = now;
    write_new_inode(super_, target_ino, &disk)?;

    // Step 2: splice a new dirent into the parent directory block. If
    // add_link fails, unwind the link-count bump so we don't leak a
    // phantom reference.
    let file_type = filetype_from_mode(disk.i_mode);
    if let Err(e) = add_link(super_, parent, name, target_ino, file_type) {
        // Revert the link count. If the re-write fails the on-disk
        // count is inflated by 1; `e2fsck` trims it. Intentionally log-
        // and-drop the secondary error — we already have an error to
        // propagate.
        disk.i_links_count = disk.i_links_count.saturating_sub(1);
        let _ = write_new_inode(super_, target_ino, &disk);
        return Err(e);
    }

    // Mirror the bump in the target Inode's in-memory VFS meta so
    // subsequent `stat()` calls (which read through `InodeOps::getattr`
    // or the cached `Inode::meta`) see the new nlink without a fresh
    // iget.
    {
        let mut meta = target.meta.write();
        meta.nlink = meta.nlink.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Symbolic link — InodeOps::symlink
// ---------------------------------------------------------------------------

/// Create a new symlink `name` in `parent` whose target is `target`.
/// Picks fast vs. slow layout by length. Returns the freshly-published
/// `Arc<Inode>` for the new symlink.
pub fn symlink(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    parent_vfs: &Inode,
    sb: &Arc<SuperBlock>,
    name: &[u8],
    target: &[u8],
) -> Result<Arc<Inode>, i64> {
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }
    validate_name(name)?;
    if parent_vfs.kind != InodeKind::Dir {
        return Err(ENOTDIR);
    }
    // Empty target is nonsensical — POSIX `symlink(2)` with an empty
    // `oldpath` returns ENOENT.
    if target.is_empty() {
        return Err(ENOENT);
    }
    if target.len() > EXT2_SYMLINK_TARGET_MAX {
        return Err(ENAMETOOLONG);
    }

    let _parent_guard = parent_vfs.dir_rwsem.write();

    match super::dir::lookup(super_, parent, name) {
        Ok(_) => return Err(EEXIST),
        Err(e) if e == ENOENT => {}
        Err(e) => return Err(e),
    }

    let inodes_per_group = super_.sb_disk.lock().s_inodes_per_group;
    let parent_group = if inodes_per_group == 0 {
        None
    } else {
        Some((parent.ino - 1) / inodes_per_group)
    };

    // Step 1: ialloc.
    let new_ino = alloc_inode(super_, parent_group, false)?;

    // Mirror create_common's unwind gate. `linked = true` after
    // add_link succeeds; after that point a failure must NOT free the
    // inode (a dirent on disk points at it). `data_block` tracks a
    // slow-symlink data block so pre-link failures can free it too.
    let mut data_block: Option<u32> = None;
    let mut linked = false;

    let outcome: Result<Arc<Inode>, i64> = (|| {
        let now = Timespec::now().sec as u32;
        let fast = target.len() <= EXT2_FAST_SYMLINK_MAX as usize;
        let block_size = super_.block_size;

        // Build the initial on-disk inode with the inline target (fast
        // path). For slow symlinks this just zero-stamps i_block[]; we
        // re-emit below with the allocated block number.
        let mut i_block = [0u32; EXT2_N_BLOCKS];
        if fast {
            // Inline encoding: concatenate target bytes into the 60-byte
            // i_block[] region as little-endian u32s. See the matching
            // decoder in `super::symlink::inline_bytes`.
            let mut raw = [0u8; 60];
            raw[..target.len()].copy_from_slice(target);
            for (i, slot) in i_block.iter_mut().enumerate() {
                let off = 4 * i;
                *slot = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
            }
        }

        let i_mode: u16 = 0o120_000 | 0o777; // S_IFLNK | 0o777
        let i_blocks_sectors: u32 = if fast { 0 } else { block_size / 512 };

        let mut disk = DiskInode {
            i_mode,
            i_uid: 0,
            i_size: target.len() as u32,
            i_atime: now,
            i_ctime: now,
            i_mtime: now,
            i_dtime: 0,
            i_gid: 0,
            i_links_count: 1,
            i_blocks: i_blocks_sectors,
            i_flags: 0,
            i_block,
            i_dir_acl_or_size_high: 0,
            l_i_uid_high: 0,
            l_i_gid_high: 0,
        };

        // Slow path: allocate a data block, write the target into it,
        // then stamp i_block[0] before the first on-disk encode.
        if !fast {
            let blk = super::balloc::alloc_block(super_, parent_group)?;
            data_block = Some(blk);
            write_slow_symlink_target(super_, blk, target, block_size)?;
            disk.i_block[0] = blk;
        }

        // Step 2: encode the inode + flush.
        write_new_inode(super_, new_ino, &disk)?;

        // Step 3: insert the dirent.
        add_link(super_, parent, name, new_ino, EXT2_FT_SYMLINK)?;
        linked = true;

        // Publish the fresh inode via the per-mount cache.
        iget(super_, sb, new_ino)
    })();

    match outcome {
        Ok(inode) => Ok(inode),
        Err(e) => {
            if !linked {
                if let Some(blk) = data_block {
                    let _ = super::balloc::free_block(super_, blk);
                }
                let _ = free_inode(super_, new_ino, false);
            }
            // If linked == true the dirent points at the inode; the
            // e2fsck path reconciles any leaked resources if a later
            // step (currently only `iget`) fails.
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map the inode's `i_mode` S_IFMT bits to the ext2 `file_type` byte
/// used in dirents when `INCOMPAT_FILETYPE` is on (the golden image
/// plus every modern ext2 image does carry this flag). Unknown modes
/// round-trip to `EXT2_FT_UNKNOWN`; the dirent walker treats that as
/// the "check via ino->mode" fallback.
fn filetype_from_mode(mode: u16) -> u8 {
    use super::disk::{
        EXT2_FT_BLKDEV, EXT2_FT_CHRDEV, EXT2_FT_DIR, EXT2_FT_FIFO, EXT2_FT_REG_FILE, EXT2_FT_SOCK,
        EXT2_FT_UNKNOWN,
    };
    match mode & 0o170_000 {
        0o100_000 => EXT2_FT_REG_FILE,
        0o040_000 => EXT2_FT_DIR,
        0o120_000 => EXT2_FT_SYMLINK,
        0o020_000 => EXT2_FT_CHRDEV,
        0o060_000 => EXT2_FT_BLKDEV,
        0o010_000 => EXT2_FT_FIFO,
        0o140_000 => EXT2_FT_SOCK,
        _ => EXT2_FT_UNKNOWN,
    }
}

/// Write the slow-symlink target into `blk`, zeroing any trailing
/// bytes inside the block so readers don't observe stale data. The
/// buffer-cache page for a freshly-allocated data block may carry
/// whatever bytes the slot held in its previous incarnation — zero
/// the whole block first.
fn write_slow_symlink_target(
    super_: &Arc<Ext2Super>,
    blk: u32,
    target: &[u8],
    block_size: u32,
) -> Result<(), i64> {
    if target.len() > block_size as usize {
        // Shouldn't happen — the caller already clamped to
        // EXT2_SYMLINK_TARGET_MAX (4095), and every ext2 `block_size`
        // (1 KiB … 4 KiB) is ≥ 4095 except the 1 KiB case. On a 1 KiB
        // FS with a >1024-byte target we'd need multi-block slow
        // symlinks, which this wave doesn't implement; surface as
        // ENAMETOOLONG so the caller can report it cleanly.
        return Err(ENAMETOOLONG);
    }
    let bh = super_
        .cache
        .bread(super_.device_id, blk as u64)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        if (block_size as usize) > data.len() {
            return Err(EIO);
        }
        for b in data[..block_size as usize].iter_mut() {
            *b = 0;
        }
        data[..target.len()].copy_from_slice(target);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetype_from_mode_covers_all_ifmts() {
        use super::super::disk::{
            EXT2_FT_BLKDEV, EXT2_FT_CHRDEV, EXT2_FT_DIR, EXT2_FT_FIFO, EXT2_FT_REG_FILE,
            EXT2_FT_SOCK, EXT2_FT_UNKNOWN,
        };
        assert_eq!(filetype_from_mode(0o100_644), EXT2_FT_REG_FILE);
        assert_eq!(filetype_from_mode(0o040_755), EXT2_FT_DIR);
        assert_eq!(filetype_from_mode(0o120_777), EXT2_FT_SYMLINK);
        assert_eq!(filetype_from_mode(0o020_666), EXT2_FT_CHRDEV);
        assert_eq!(filetype_from_mode(0o060_600), EXT2_FT_BLKDEV);
        assert_eq!(filetype_from_mode(0o010_644), EXT2_FT_FIFO);
        assert_eq!(filetype_from_mode(0o140_600), EXT2_FT_SOCK);
        // Unknown S_IFMT → EXT2_FT_UNKNOWN.
        assert_eq!(filetype_from_mode(0o000_644), EXT2_FT_UNKNOWN);
    }

    #[test]
    fn fast_symlink_bound_is_60_bytes() {
        // Matches the read-path gate in super::symlink.
        assert_eq!(EXT2_FAST_SYMLINK_MAX, 60);
    }

    #[test]
    fn link_max_is_u16_max() {
        assert_eq!(EXT2_LINK_MAX, u16::MAX);
    }

    #[test]
    fn symlink_target_max_matches_path_max_minus_nul() {
        // PATH_MAX = 4096 including trailing NUL.
        assert_eq!(EXT2_SYMLINK_TARGET_MAX, 4095);
    }
}
