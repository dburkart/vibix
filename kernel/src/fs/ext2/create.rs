//! ext2 namespace-mutation paths — `create` / `mkdir` / `mknod`.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Write Ordering
//! is the normative spec. Issue #568 (Workstream E) lands the
//! `InodeOps`-shaped helpers that allocate a new inode and hook it into
//! a parent directory. The sibling `free_inode` plus `balloc::{alloc,
//! free}_block` primitives (#565 / #566) are the underlying building
//! blocks.
//!
//! # Normative ordering (RFC 0004 §Write Ordering)
//!
//! Every create path runs the same on-disk sequence:
//!
//! 1. `alloc_inode` — claim a bitmap bit, bump `bg_free_inodes_count`
//!    and `s_free_inodes_count`. The allocator's inside flushes the
//!    bitmap block *first*, then the BGDT, then the superblock.
//! 2. `write_new_inode` — RMW the inode-table slot with the fresh
//!    `i_mode` / uid / gid / size / timestamps / `i_links_count`.
//!    Sync-flush so a later "add dirent" can't complete before the
//!    inode itself is on disk.
//! 3. *(mkdir only)* `alloc_block` one data block, stamp `.` and `..`
//!    dirents into it, flush. Then re-write the inode with the
//!    single `i_block[0]` pointer + `i_size = block_size` + `i_blocks
//!    = block_size / 512`.
//! 4. `add_link` — walk the parent's data blocks, find a slot whose
//!    trailing slack can be split into a fresh record for the new
//!    name, or allocate a new parent data block and install the
//!    record at offset 0. Flush the parent block.
//! 5. *(mkdir only)* Bump the parent's `i_links_count` (for the new
//!    subdir's `..` back-link) and write it back via the RMW path.
//!
//! The sequence is strictly "inode-first, dirent-last" so a crash at
//! any step leaves the filesystem in a state `e2fsck -y` can reconcile:
//!
//! - Crash between 1 and 2: inode bit is set but its mode/dtime reads as
//!   zero. `e2fsck` treats this as an orphan inode and frees it.
//! - Crash between 2 and 4: inode is fully stamped but no dirent points
//!   at it. Same outcome — `e2fsck` detects `i_links_count > 0` with no
//!   reachable parent and frees the inode.
//! - Crash mid-step-4: parent block is half-written. The buffer cache's
//!   `sync_dirty_buffer` is synchronous, so this is bounded to the
//!   single 4 KiB write; the ext2 format's 4-byte-aligned records mean a
//!   torn write surfaces as one short-rec_len corruption that `e2fsck`
//!   flags and skips.
//!
//! The reverse order (dirent first, inode last) would expose a dirent
//! pointing at an uninitialised inode — a reader following that record
//! would decode garbage as mode/size, which is precisely the
//! confused-deputy scenario RFC 0004 §Security calls out.
//!
//! # Failure / unwind
//!
//! If step 2 fails, the already-allocated inode is freed via
//! [`ialloc::free_inode`](super::ialloc::free_inode). If step 3 fails
//! (mkdir's data-block alloc), the inode is freed too. If step 4 fails
//! (no dirent slot, parent-block read error), the inode (and, for
//! mkdir, the data block) is freed; the parent directory observes no
//! on-disk change. Step 5 failure after the dirent has been inserted
//! leaves a valid directory with a stale `i_links_count` on the
//! *parent*; `e2fsck` fixes that cheaply.
//!
//! # What this module does *not* do
//!
//! - `unlink` / `rmdir` / `rename` — sibling issue #569.
//! - HTree (`dir_index`) acceleration — explicitly out of scope per the
//!   RFC.
//! - Permission checks. The VFS's `InodeOps::{create,mkdir}` trait
//!   signatures don't carry a `Credential` today; the caller
//!   (`path_walk`'s permission-check pass) is responsible for running
//!   `permission(parent, MAY_WRITE | MAY_EXEC, cred)` before routing to
//!   this module.

use alloc::sync::Arc;
use alloc::vec;

use super::disk::{
    align4_rec_len, Ext2DirEntry2, Ext2Inode as DiskInode, EXT2_DIR_REC_HEADER_LEN, EXT2_FT_BLKDEV,
    EXT2_FT_CHRDEV, EXT2_FT_DIR, EXT2_FT_FIFO, EXT2_FT_REG_FILE, EXT2_FT_SOCK, EXT2_INODE_SIZE_V0,
    EXT2_N_BLOCKS,
};
use super::fs::{Ext2MountFlags, Ext2Super};
use super::ialloc::{alloc_inode, free_inode};
use super::inode::{iget, Ext2Inode};

use crate::fs::vfs::inode::{Inode, InodeKind};
use crate::fs::vfs::super_block::SuperBlock;
use crate::fs::vfs::Timespec;
use crate::fs::{EEXIST, EINVAL, EIO, ENAMETOOLONG, ENOSPC, ENOTDIR, EPERM, EROFS};

/// POSIX `NAME_MAX` for ext2. On-disk `name_len` is `u8`; the spec caps
/// file names at 255 bytes, matching the field width.
pub const EXT2_NAME_MAX: usize = 255;

// ---------------------------------------------------------------------------
// Public entry points — one per op-vector slot
// ---------------------------------------------------------------------------

/// Create a regular file `name` under `parent`. Returns the fresh
/// `Arc<Inode>` (ino published through the per-mount inode cache).
pub fn create_file(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    parent_vfs: &Inode,
    sb: &Arc<SuperBlock>,
    name: &[u8],
    mode: u16,
) -> Result<Arc<Inode>, i64> {
    create_common(
        super_,
        parent,
        parent_vfs,
        sb,
        name,
        NewNode::Regular { mode },
    )
}

/// Create a subdirectory `name` under `parent`. Allocates a data block
/// for the new dir and stamps `.` / `..` into it, then bumps the
/// parent's `i_links_count`.
pub fn create_dir(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    parent_vfs: &Inode,
    sb: &Arc<SuperBlock>,
    name: &[u8],
    mode: u16,
) -> Result<Arc<Inode>, i64> {
    create_common(
        super_,
        parent,
        parent_vfs,
        sb,
        name,
        NewNode::Directory { mode },
    )
}

/// Create a special-file (`chr`, `blk`, `fifo`, `sock`) entry named
/// `name` under `parent`. `rdev` is the encoded `(major, minor)` value
/// for character / block devices; FIFOs and sockets pass `0`.
pub fn mknod(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    parent_vfs: &Inode,
    sb: &Arc<SuperBlock>,
    name: &[u8],
    kind: InodeKind,
    mode: u16,
    rdev: u64,
) -> Result<Arc<Inode>, i64> {
    match kind {
        InodeKind::Chr | InodeKind::Blk => {}
        InodeKind::Fifo | InodeKind::Sock => {
            // FIFOs and sockets must not carry a device number; reject
            // a non-zero rdev defensively rather than silently stamp
            // garbage into i_block[0].
            if rdev != 0 {
                return Err(EINVAL);
            }
        }
        _ => return Err(EINVAL),
    }
    create_common(
        super_,
        parent,
        parent_vfs,
        sb,
        name,
        NewNode::Special { kind, mode, rdev },
    )
}

// ---------------------------------------------------------------------------
// Common pipeline
// ---------------------------------------------------------------------------

/// What we're about to create. Drives the ftype/mode decisions and
/// (for directories) the post-alloc data-block setup.
enum NewNode {
    Regular {
        mode: u16,
    },
    Directory {
        mode: u16,
    },
    Special {
        kind: InodeKind,
        mode: u16,
        rdev: u64,
    },
}

impl NewNode {
    fn is_dir(&self) -> bool {
        matches!(self, NewNode::Directory { .. })
    }
    fn file_type(&self) -> u8 {
        match self {
            NewNode::Regular { .. } => EXT2_FT_REG_FILE,
            NewNode::Directory { .. } => EXT2_FT_DIR,
            NewNode::Special { kind, .. } => match kind {
                InodeKind::Chr => EXT2_FT_CHRDEV,
                InodeKind::Blk => EXT2_FT_BLKDEV,
                InodeKind::Fifo => EXT2_FT_FIFO,
                InodeKind::Sock => EXT2_FT_SOCK,
                _ => 0,
            },
        }
    }
    /// Compose the 16-bit on-disk `i_mode`: S_IFMT bits + the caller's
    /// permission bits (masked to 0o7777).
    fn i_mode(&self) -> u16 {
        let (ifmt, perm) = match self {
            NewNode::Regular { mode } => (0o100_000, *mode),
            NewNode::Directory { mode } => (0o040_000, *mode),
            NewNode::Special { kind, mode, .. } => {
                let ifmt = match kind {
                    InodeKind::Chr => 0o020_000,
                    InodeKind::Blk => 0o060_000,
                    InodeKind::Fifo => 0o010_000,
                    InodeKind::Sock => 0o140_000,
                    _ => 0,
                };
                (ifmt, *mode)
            }
        };
        (ifmt | (perm & 0o7_777)) as u16
    }
}

fn create_common(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    parent_vfs: &Inode,
    sb: &Arc<SuperBlock>,
    name: &[u8],
    nn: NewNode,
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

    // Serialise directory mutations on the parent. The VFS's
    // `dir_rwsem` write lock guarantees at most one create at a time
    // observes this parent — so the `lookup`-then-`add_link` pair is
    // atomic from the caller's perspective.
    let _parent_guard = parent_vfs.dir_rwsem.write();

    // Reject duplicate name up front. `EEXIST` matches POSIX.
    if super::dir::lookup(super_, parent, name).is_ok() {
        return Err(EEXIST);
    }

    // Group hint: place the new inode in the parent's group to
    // encourage data-locality (RFC 0004 §Allocator).
    let inodes_per_group = super_.sb_disk.lock().s_inodes_per_group;
    let parent_group = if inodes_per_group == 0 {
        None
    } else {
        Some((parent.ino - 1) / inodes_per_group)
    };

    // Step 1: inode-bitmap alloc.
    let new_ino = alloc_inode(super_, parent_group, nn.is_dir())?;

    // Everything below cleans up the inode via `free_inode` on failure.
    // For `mkdir`, also free the allocated data block if we get past
    // step 3.
    let mut dir_block: Option<u32> = None;

    let outcome: Result<Arc<Inode>, i64> = (|| {
        let links_count: u16 = if nn.is_dir() { 2 } else { 1 };
        let now = Timespec::now().sec as u32;

        // Step 2: build the on-disk inode and write it.
        let i_mode = nn.i_mode();
        let mut i_block = [0u32; EXT2_N_BLOCKS];
        let (i_size, i_blocks) = match &nn {
            NewNode::Special { kind, rdev, .. } => match kind {
                InodeKind::Chr | InodeKind::Blk => {
                    // Stash the encoded rdev in i_block[0] per ext2
                    // convention. Linux's `ext2_iget` reads it through
                    // `old_decode_dev` / `new_decode_dev`; the
                    // low-16-bits placement matches "old" rdev which
                    // every consumer groks.
                    i_block[0] = *rdev as u32;
                    (0u64, 0u32)
                }
                _ => (0u64, 0u32),
            },
            _ => (0u64, 0u32),
        };

        let disk = DiskInode {
            i_mode,
            i_uid: 0,
            i_size: i_size as u32,
            i_atime: now,
            i_ctime: now,
            i_mtime: now,
            i_dtime: 0,
            i_gid: 0,
            i_links_count: links_count,
            i_blocks,
            i_flags: 0,
            i_block,
            i_dir_acl_or_size_high: 0,
            l_i_uid_high: 0,
            l_i_gid_high: 0,
        };
        write_new_inode(super_, new_ino, &disk)?;

        // Step 3 (mkdir only): allocate a data block and stamp
        // `.` / `..` dirents. Then re-emit the inode with the block
        // pointer and the new size.
        if nn.is_dir() {
            let data_blk = super::balloc::alloc_block(super_, parent_group)?;
            dir_block = Some(data_blk);
            stamp_dot_dotdot(super_, data_blk, new_ino, parent_vfs.ino as u32)?;

            let block_size = super_.block_size;
            let mut dir_disk = disk.clone();
            dir_disk.i_block[0] = data_blk;
            dir_disk.i_size = block_size;
            // i_blocks is in 512-byte sectors.
            dir_disk.i_blocks = block_size / 512;
            write_new_inode(super_, new_ino, &dir_disk)?;
        }

        // Step 4: link the new inode into the parent directory.
        add_link(super_, parent, name, new_ino, nn.file_type())?;

        // Step 5 (mkdir only): bump parent's `i_links_count` for the
        // new subdir's `..`.
        if nn.is_dir() {
            bump_parent_links(super_, parent, parent_vfs.ino as u32, 1)?;
        }

        // Publish the fresh inode via the per-mount inode cache.
        iget(super_, sb, new_ino)
    })();

    match outcome {
        Ok(inode) => Ok(inode),
        Err(e) => {
            // Unwind: free the data block first (if we allocated one
            // for a dir), then the inode. Log-and-drop secondary
            // failures — we already have an error to propagate.
            if let Some(blk) = dir_block {
                let _ = super::balloc::free_block(super_, blk);
            }
            let _ = free_inode(super_, new_ino, nn.is_dir());
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Inode-table RMW
// ---------------------------------------------------------------------------

/// Locate the inode-table slot for `ino` and overlay the driver-owned
/// fields of `disk`. Preserves the tail (on-disk rev-1 images store a
/// larger slot that carries fields we don't decode) via
/// [`DiskInode::encode_to_slot`].
fn write_new_inode(super_: &Arc<Ext2Super>, ino: u32, disk: &DiskInode) -> Result<(), i64> {
    if ino == 0 {
        return Err(EINVAL);
    }
    let (inodes_per_group, _inodes_count) = {
        let sb = super_.sb_disk.lock();
        (sb.s_inodes_per_group, sb.s_inodes_count)
    };
    if inodes_per_group == 0 {
        return Err(EIO);
    }
    let group = (ino - 1) / inodes_per_group;
    let index_in_group = (ino - 1) % inodes_per_group;
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

// ---------------------------------------------------------------------------
// Parent-directory dirent insert
// ---------------------------------------------------------------------------

/// Insert a record `{child_ino, name, file_type}` into `parent`'s
/// directory data blocks. Walks existing blocks looking for slack in a
/// trailing record big enough to split; allocates a new direct data
/// block if none of the existing blocks has room.
///
/// RFC 0004 §Directory operations: the "split a trailing record" case
/// is the standard ext2 in-place insert — the last live record in each
/// block is grown to fill the whole block, so its `rec_len` can always
/// be shortened to the minimal-aligned size and the remainder re-used
/// for a new record.
///
/// Only uses the inode's direct pointers (`i_block[0..12]`) in this
/// wave; directories that outgrow 12 blocks need the indirect-block
/// walker's write path, which is Workstream F scope.
fn add_link(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    name: &[u8],
    child_ino: u32,
    file_type: u8,
) -> Result<(), i64> {
    let block_size = super_.block_size;
    if block_size == 0 {
        return Err(EIO);
    }
    let needed = align4_rec_len(EXT2_DIR_REC_HEADER_LEN + name.len()).ok_or(ENAMETOOLONG)?;
    if needed > block_size as usize {
        return Err(ENAMETOOLONG);
    }

    // Snapshot the parent's direct block pointers + current size.
    let (i_block, dir_size) = {
        let meta = parent.meta.read();
        (meta.i_block, meta.size)
    };

    // Try to fit the record into an existing block. We walk only the
    // direct slots for now.
    let direct_count = super::indirect::EXT2_DIRECT_BLOCKS.min(EXT2_N_BLOCKS);
    for (_logical, slot) in i_block.iter().take(direct_count).enumerate() {
        if *slot == 0 {
            continue;
        }
        if try_insert_into_block(super_, *slot, name, child_ino, file_type, needed)? {
            return Ok(());
        }
    }

    // No slack anywhere — allocate a new data block and install the
    // record at offset 0. Pick the first free direct slot.
    let (free_idx, _) = i_block
        .iter()
        .take(direct_count)
        .enumerate()
        .find(|(_, slot)| **slot == 0)
        .ok_or(ENOSPC)?;

    let parent_group = {
        let ipg = super_.sb_disk.lock().s_inodes_per_group;
        if ipg == 0 {
            None
        } else {
            Some((parent.ino - 1) / ipg)
        }
    };
    let new_blk = super::balloc::alloc_block(super_, parent_group)?;

    // Install the record at offset 0 with rec_len spanning the whole
    // block (so the next insert can split the slack cleanly).
    if let Err(e) = stamp_fresh_dir_block(super_, new_blk, child_ino, file_type, name, block_size) {
        let _ = super::balloc::free_block(super_, new_blk);
        return Err(e);
    }

    // Update the parent inode: pointer + size + i_blocks.
    let new_size = dir_size.saturating_add(block_size as u64);
    patch_parent_inode_block(super_, parent, free_idx, new_blk, new_size, block_size)?;

    Ok(())
}

/// Scan `blk`'s records, shrink the last one's `rec_len` to the
/// minimum 4-byte-aligned size, and install the new record in the
/// recovered slack. Returns `Ok(true)` if the insert succeeded,
/// `Ok(false)` if the block is already full (no record has enough
/// slack).
fn try_insert_into_block(
    super_: &Arc<Ext2Super>,
    blk: u32,
    name: &[u8],
    child_ino: u32,
    file_type: u8,
    needed: usize,
) -> Result<bool, i64> {
    let bh = super_
        .cache
        .bread(super_.device_id, blk as u64)
        .map_err(|_| EIO)?;
    let done = {
        let mut data = bh.data.write();
        let block_size = data.len();

        let mut cursor = 0usize;
        let mut last_start: Option<usize> = None;
        let mut last_header: Option<Ext2DirEntry2> = None;
        while cursor + EXT2_DIR_REC_HEADER_LEN <= block_size {
            let hdr = Ext2DirEntry2::decode_header(&data[cursor..cursor + EXT2_DIR_REC_HEADER_LEN]);
            let rec_len = hdr.rec_len as usize;
            if rec_len < EXT2_DIR_REC_HEADER_LEN
                || rec_len % 4 != 0
                || cursor + rec_len > block_size
            {
                // Corruption: bail — don't try to insert into a lying
                // block. Surface as EIO to force the caller to react.
                return Err(EIO);
            }
            last_start = Some(cursor);
            last_header = Some(hdr.clone());

            // Try the split-in-place: minimal footprint this record
            // needs is align4(8 + name_len). The slack is
            // rec_len - minimal. If the slack is >= needed, split.
            let minimal =
                align4_rec_len(EXT2_DIR_REC_HEADER_LEN + hdr.name_len as usize).ok_or(EIO)?;
            if rec_len >= minimal.saturating_add(needed) && hdr.inode != 0 {
                // Shrink current record; install new record in the
                // slack.
                let new_slack = rec_len - minimal;
                let mut shrunk = hdr.clone();
                shrunk.rec_len = minimal as u16;
                shrunk.encode_header_to_slot(&mut data[cursor..cursor + EXT2_DIR_REC_HEADER_LEN]);

                let new_start = cursor + minimal;
                emit_dirent_into(
                    &mut data[new_start..new_start + new_slack],
                    child_ino,
                    file_type,
                    name,
                    new_slack,
                );
                return Ok(true);
            }

            // Also handle the "whole record is a tombstone" case — an
            // entry with inode == 0 can be overwritten outright if its
            // rec_len >= needed.
            if hdr.inode == 0 && rec_len >= needed {
                emit_dirent_into(
                    &mut data[cursor..cursor + rec_len],
                    child_ino,
                    file_type,
                    name,
                    rec_len,
                );
                return Ok(true);
            }

            cursor += rec_len;
        }

        // Last resort: if we walked the whole block and the final
        // record's slack *still* isn't enough, we're stuck with this
        // block. Tell the caller to try the next one.
        let _ = (last_start, last_header);
        false
    };

    if done {
        super_.cache.mark_dirty(&bh);
        super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    }
    Ok(done)
}

/// Stamp a freshly-allocated directory block with a single record
/// spanning the entire block.
fn stamp_fresh_dir_block(
    super_: &Arc<Ext2Super>,
    blk: u32,
    child_ino: u32,
    file_type: u8,
    name: &[u8],
    block_size: u32,
) -> Result<(), i64> {
    let bh = super_
        .cache
        .bread(super_.device_id, blk as u64)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        if (block_size as usize) > data.len() {
            return Err(EIO);
        }
        // Zero the block first — the freshly-allocated block's buffer-
        // cache page may carry stale bytes from a prior mount of the
        // same slot. A directory block with trailing garbage looks
        // corrupt to the DirEntryIter (unknown file_type / bogus
        // rec_len) and would surface as EIO on the next lookup.
        for b in data[..block_size as usize].iter_mut() {
            *b = 0;
        }
        emit_dirent_into(
            &mut data[..block_size as usize],
            child_ino,
            file_type,
            name,
            block_size as usize,
        );
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Write a single directory record into `slot`, with `rec_len` spanning
/// the whole slot (the "trailing record" convention). Zero-fills the
/// padding between the name and `rec_len`.
fn emit_dirent_into(slot: &mut [u8], ino: u32, file_type: u8, name: &[u8], rec_len: usize) {
    debug_assert!(rec_len >= EXT2_DIR_REC_HEADER_LEN + name.len());
    // Zero the full slot first so padding + any leftover bytes of the
    // prior (overwritten) record are blanked.
    for b in slot[..rec_len].iter_mut() {
        *b = 0;
    }
    let hdr = Ext2DirEntry2 {
        inode: ino,
        rec_len: rec_len as u16,
        name_len: name.len() as u8,
        file_type,
    };
    hdr.encode_header_to_slot(&mut slot[..EXT2_DIR_REC_HEADER_LEN]);
    slot[EXT2_DIR_REC_HEADER_LEN..EXT2_DIR_REC_HEADER_LEN + name.len()].copy_from_slice(name);
}

/// Stamp the `.` / `..` records into a freshly-allocated directory data
/// block. Layout per RFC 0004 §Directory operations:
///
/// - record 0: inode = `new_ino`, name = `.`,  rec_len = 12
/// - record 1: inode = `parent_ino`, name = `..`, rec_len = block_size - 12
fn stamp_dot_dotdot(
    super_: &Arc<Ext2Super>,
    blk: u32,
    new_ino: u32,
    parent_ino: u32,
) -> Result<(), i64> {
    let block_size = super_.block_size as usize;
    if block_size < 24 {
        return Err(EIO);
    }
    let bh = super_
        .cache
        .bread(super_.device_id, blk as u64)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        if block_size > data.len() {
            return Err(EIO);
        }
        for b in data[..block_size].iter_mut() {
            *b = 0;
        }
        // `.`  — 12-byte record.
        emit_dirent_into(&mut data[0..12], new_ino, EXT2_FT_DIR, b".", 12);
        // `..` — spans the rest.
        let dotdot_len = block_size - 12;
        emit_dirent_into(
            &mut data[12..12 + dotdot_len],
            parent_ino,
            EXT2_FT_DIR,
            b"..",
            dotdot_len,
        );
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Parent-inode mutators
// ---------------------------------------------------------------------------

/// Write back the parent's inode after we've added a new direct data
/// block. Updates the in-memory meta as well as the on-disk slot so a
/// subsequent lookup sees the enlarged directory.
fn patch_parent_inode_block(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    block_idx: usize,
    block_no: u32,
    new_size: u64,
    block_size: u32,
) -> Result<(), i64> {
    // Re-read the on-disk slot so we preserve every field this driver
    // doesn't own, then overlay the two we do.
    let slot = read_inode_slot(super_, parent.ino)?;
    let mut disk = DiskInode::decode(&slot);
    disk.i_block[block_idx] = block_no;
    disk.i_size = new_size as u32;
    disk.i_blocks = disk.i_blocks.saturating_add(block_size / 512);
    write_new_inode(super_, parent.ino, &disk)?;

    // Mirror the update in the in-memory meta so the parent's
    // `dir::lookup` / `getdents64` observe the new block on the next
    // walk.
    {
        let mut meta = parent.meta.write();
        meta.i_block[block_idx] = block_no;
        meta.size = new_size;
        meta.i_blocks = meta.i_blocks.saturating_add(block_size / 512);
    }
    Ok(())
}

/// Bump (or decrement) the parent's `i_links_count` by `delta`. Called
/// by `mkdir` to account for the new subdir's `..` back-link.
fn bump_parent_links(
    super_: &Arc<Ext2Super>,
    parent: &Ext2Inode,
    parent_ino: u32,
    delta: i32,
) -> Result<(), i64> {
    let slot = read_inode_slot(super_, parent_ino)?;
    let mut disk = DiskInode::decode(&slot);
    if delta >= 0 {
        disk.i_links_count = disk.i_links_count.saturating_add(delta as u16);
    } else {
        disk.i_links_count = disk.i_links_count.saturating_sub((-delta) as u16);
    }
    write_new_inode(super_, parent_ino, &disk)?;

    // Mirror the in-memory parent meta. The VFS `Inode`'s `nlink` is
    // reflected via `getattr` through the ext2 meta so `stat()` reads
    // the fresh value.
    {
        let mut meta = parent.meta.write();
        if delta >= 0 {
            meta.links_count = meta.links_count.saturating_add(delta as u16);
        } else {
            meta.links_count = meta.links_count.saturating_sub((-delta) as u16);
        }
    }
    Ok(())
}

/// Read a 128-byte inode slot through the buffer cache. Shared with
/// [`write_new_inode`]; kept as a helper so the RMW discipline in the
/// module docs stays honest.
fn read_inode_slot(super_: &Arc<Ext2Super>, ino: u32) -> Result<alloc::vec::Vec<u8>, i64> {
    if ino == 0 {
        return Err(EINVAL);
    }
    let inodes_per_group = super_.sb_disk.lock().s_inodes_per_group;
    if inodes_per_group == 0 {
        return Err(EIO);
    }
    let group = (ino - 1) / inodes_per_group;
    let index_in_group = (ino - 1) % inodes_per_group;
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
    let mut out = vec![0u8; EXT2_INODE_SIZE_V0];
    {
        let data = bh.data.read();
        if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
            return Err(EIO);
        }
        out.copy_from_slice(&data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0]);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate a proposed directory-entry name.
///
/// - Non-empty.
/// - Does not exceed `EXT2_NAME_MAX`.
/// - Not `.` or `..` (these are synthesised by `mkdir` / the iterator,
///   not creatable by userspace).
/// - Contains no NUL bytes or `/` separators.
fn validate_name(name: &[u8]) -> Result<(), i64> {
    if name.is_empty() {
        return Err(EINVAL);
    }
    if name.len() > EXT2_NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    if name == b"." || name == b".." {
        return Err(EEXIST);
    }
    if name.iter().any(|&b| b == 0 || b == b'/') {
        return Err(EINVAL);
    }
    Ok(())
}

// The EPERM constant is only reached in rare permission paths; keep the
// import so a future tightening doesn't chase a missing symbol.
const _: i64 = EPERM;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_accepts_normal() {
        assert!(validate_name(b"hello").is_ok());
        assert!(validate_name(b"file.txt").is_ok());
        assert!(validate_name(b"a").is_ok());
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert_eq!(validate_name(b""), Err(EINVAL));
    }

    #[test]
    fn validate_name_rejects_dot_and_dotdot() {
        assert_eq!(validate_name(b"."), Err(EEXIST));
        assert_eq!(validate_name(b".."), Err(EEXIST));
    }

    #[test]
    fn validate_name_rejects_slash_and_nul() {
        assert_eq!(validate_name(b"a/b"), Err(EINVAL));
        assert_eq!(validate_name(b"a\0b"), Err(EINVAL));
    }

    #[test]
    fn validate_name_rejects_too_long() {
        let long = vec![b'a'; EXT2_NAME_MAX + 1];
        assert_eq!(validate_name(&long), Err(ENAMETOOLONG));
        let boundary = vec![b'a'; EXT2_NAME_MAX];
        assert!(validate_name(&boundary).is_ok());
    }

    #[test]
    fn new_node_file_type_matches_kind() {
        assert_eq!(NewNode::Regular { mode: 0 }.file_type(), EXT2_FT_REG_FILE);
        assert_eq!(NewNode::Directory { mode: 0 }.file_type(), EXT2_FT_DIR);
        assert_eq!(
            NewNode::Special {
                kind: InodeKind::Chr,
                mode: 0,
                rdev: 0
            }
            .file_type(),
            EXT2_FT_CHRDEV
        );
        assert_eq!(
            NewNode::Special {
                kind: InodeKind::Blk,
                mode: 0,
                rdev: 0
            }
            .file_type(),
            EXT2_FT_BLKDEV
        );
        assert_eq!(
            NewNode::Special {
                kind: InodeKind::Fifo,
                mode: 0,
                rdev: 0
            }
            .file_type(),
            EXT2_FT_FIFO
        );
        assert_eq!(
            NewNode::Special {
                kind: InodeKind::Sock,
                mode: 0,
                rdev: 0
            }
            .file_type(),
            EXT2_FT_SOCK
        );
    }

    #[test]
    fn new_node_i_mode_composes_ifmt_and_perm() {
        // Regular: S_IFREG | 0o644.
        assert_eq!(NewNode::Regular { mode: 0o644 }.i_mode(), 0o100_644);
        // Directory: S_IFDIR | 0o755.
        assert_eq!(NewNode::Directory { mode: 0o755 }.i_mode(), 0o040_755);
        // Char device: S_IFCHR | 0o666.
        assert_eq!(
            NewNode::Special {
                kind: InodeKind::Chr,
                mode: 0o666,
                rdev: 0
            }
            .i_mode(),
            0o020_666
        );
        // Perm bits above 0o7777 must be masked out to avoid leaking
        // into S_IFMT.
        assert_eq!(
            NewNode::Regular { mode: 0o177_777 }.i_mode() & 0o170_000,
            0o100_000
        );
    }

    #[test]
    fn emit_dirent_into_round_trip() {
        let mut slot = [0u8; 32];
        emit_dirent_into(&mut slot, 42, EXT2_FT_REG_FILE, b"hi", 32);
        let hdr = Ext2DirEntry2::decode_header(&slot[..EXT2_DIR_REC_HEADER_LEN]);
        assert_eq!(hdr.inode, 42);
        assert_eq!(hdr.rec_len, 32);
        assert_eq!(hdr.name_len, 2);
        assert_eq!(hdr.file_type, EXT2_FT_REG_FILE);
        assert_eq!(&slot[8..10], b"hi");
        // Padding must be zero.
        for &b in &slot[10..] {
            assert_eq!(b, 0);
        }
    }
}
