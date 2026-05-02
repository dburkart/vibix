//! ext2 `FileOps::read` — regular-file read path through the buffer
//! cache.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`), Workstream D
//! wave 2, issue #561. First user-visible sign the driver works: given
//! a live `Ext2Inode` and an `OpenFile` positioned at some `off`, copy
//! up to `buf.len()` bytes from the file into `buf`.
//!
//! # Pipeline
//!
//! For each block in `[off, off + buf.len())`:
//!
//! 1. Compute the logical file-relative block index and the in-block
//!    byte offset.
//! 2. Ask [`resolve_block`](super::indirect::resolve_block) for the
//!    absolute disk block. A sparse hole surfaces as `Ok(None)`.
//! 3. On a concrete block: `bread` through the per-mount buffer cache
//!    and copy the slice into the caller's buffer.
//! 4. On a hole: zero-fill the slice (POSIX sparse-read semantics).
//!
//! The copy length is always clamped to `min(block_size - in_block_off,
//! buf.len() - copied, i_size - off - copied)` — `i_size` (the inode's
//! byte-length) bounds the final chunk so a file whose tail doesn't
//! span a full block still returns the right count. Reads at or past
//! `i_size` return `Ok(0)` (POSIX EOF).
//!
//! # Metadata-forbidden map
//!
//! The [`indirect`](super::indirect) walker requires a
//! [`MetadataMap`](super::indirect::MetadataMap) listing the absolute
//! block ranges a data pointer is forbidden from aiming at (superblock,
//! BGDT, per-group bitmaps + inode table). Those ranges are static
//! post-mount, so they would ideally be memoised on
//! [`Ext2Super`](super::fs::Ext2Super) — but doing so would change the
//! shape of the per-mount struct, which is out of scope for #561. The
//! read path builds a fresh map per call from the BGDT; `O(groups)`
//! ranges is cheap relative to the `bread` that follows. A follow-up
//! issue ([TODO link]) promotes this to a mount-time `Arc<MetadataMap>`
//! once there's a second consumer (the write path, #565+).
//!
//! # Directory / symlink / device dispatch
//!
//! `FileOps::read` on a non-regular inode returns the POSIX-appropriate
//! errno at the entry point:
//!
//! - `Dir`  → `EISDIR`   (`read(2)` on a directory is illegal; callers
//!   use `getdents64` via the directory's own FileOps).
//! - `Link` → `EINVAL`   (symlinks are read via `readlinkat`, not
//!   `read(2)`; the inode-ops surface dispatches there).
//! - `Chr` / `Blk` / `Fifo` / `Sock` → `EINVAL` for now. In a full
//!   system the VFS would hand the fd a driver-specific `FileOps` at
//!   open-time (character-device cdev, pipe backend, …); reaching the
//!   ext2 FileOps for a special-file inode indicates the open(2) path
//!   didn't detour. Surface as `EINVAL` rather than silently misreading
//!   the inode's `i_block` (which carries `(major, minor)` for device
//!   nodes, *not* data pointers).
//!
//! # atime
//!
//! RFC 0004 §Mount calls for an `atime` bump on every read unless the
//! mount is `MS_NOATIME`. The dirty-inode writeback path is Workstream
//! E scope; until it lands any `atime` update has nowhere to go, so
//! #561 deliberately **drops** the bump. The expected-drop behaviour
//! is pinned by the integration test so a future wave that adds the
//! dirty-inode path also remembers to wire it here.

use alloc::sync::Arc;

use super::balloc::alloc_block;
use super::disk::{
    Ext2Inode as DiskInode, EXT2_INODE_SIZE_V0, EXT2_N_BLOCKS, RO_COMPAT_LARGE_FILE,
};
use super::fs::{Ext2MountFlags, Ext2Super};
use super::indirect::{
    resolve_block, Geometry, MetadataMap, WalkError, EXT2_DIND_BLOCK, EXT2_DIRECT_BLOCKS,
    EXT2_IND_BLOCK, EXT2_TIND_BLOCK,
};
use crate::fs::vfs::inode::Inode;
use crate::fs::vfs::Timespec;
use crate::fs::{EFBIG, EINVAL, EIO, EISDIR, EROFS};

/// Read at most `buf.len()` bytes from `inode` starting at byte
/// offset `off`. Short reads (fewer bytes than requested) indicate
/// either EOF (`off + n == i_size`) or the caller supplied a larger
/// buffer than the tail of the file; neither is an error.
///
/// The caller is the [`FileOps::read`](crate::fs::vfs::ops::FileOps::read)
/// impl on [`super::inode::Ext2Inode`]; exposed as a free function so
/// it's directly callable by the integration tests (they hold an
/// `Arc<Inode>` and the corresponding `Arc<Ext2Super>` already).
pub fn read_file_at(
    inode: &Inode,
    ext2_inode: &super::inode::Ext2Inode,
    buf: &mut [u8],
    off: u64,
) -> Result<usize, i64> {
    use crate::fs::vfs::inode::InodeKind;

    // Dispatch on inode kind at the entry point. Only `Reg` reads the
    // data-block chain; every other kind either has a dedicated ops
    // path (symlink → readlink, dir → getdents) or should have been
    // detoured at open(2) (device nodes, FIFOs).
    match inode.kind {
        InodeKind::Reg => {}
        InodeKind::Dir => return Err(EISDIR),
        // POSIX `read(2)` on a symlink returns EINVAL; the symlink
        // target is reached via `readlinkat` through InodeOps.
        InodeKind::Link => return Err(crate::fs::EINVAL),
        // Special-file inodes shouldn't reach ext2's FileOps — open(2)
        // is expected to bind a driver-specific FileOps at the fd.
        // EINVAL is strictly better than silently misreading the
        // `i_block` slot as data pointers.
        InodeKind::Chr | InodeKind::Blk | InodeKind::Fifo | InodeKind::Sock => {
            return Err(crate::fs::EINVAL)
        }
    }

    let super_ref = ext2_inode.super_ref.upgrade().ok_or(EIO)?;
    if buf.is_empty() {
        return Ok(0);
    }

    // Snapshot the fields we need out of the metadata lock and drop
    // the read guard before issuing any `bread`. The buffer cache can
    // sleep (blocking I/O under the hood), and holding the inode's
    // metadata lock across that would serialise every concurrent stat
    // against the slowest reader.
    let (size, i_block) = {
        let meta = ext2_inode.meta.read();
        (meta.size, meta.i_block)
    };

    if off >= size {
        return Ok(0);
    }
    let remaining_in_file = (size - off) as usize;
    let to_read = core::cmp::min(buf.len(), remaining_in_file);
    if to_read == 0 {
        return Ok(0);
    }

    let block_size = super_ref.block_size as u64;
    debug_assert!(block_size > 0, "mount validated block_size != 0");

    let (s_first_data_block, s_blocks_count) = {
        let sb = super_ref.sb_disk.lock();
        (sb.s_first_data_block, sb.s_blocks_count)
    };
    let geom =
        Geometry::new(super_ref.block_size, s_first_data_block, s_blocks_count).ok_or(EIO)?;
    let md = build_metadata_map(&super_ref);

    let mut copied = 0usize;
    while copied < to_read {
        let cur = off + copied as u64;
        let logical = cur / block_size;
        // Files above ~`u32::MAX * block_size` blocks can't exist on
        // ext2 — `s_blocks_count` is `u32`. If `logical` doesn't fit
        // in `u32`, the file has been corrupted into oblivion; bail.
        let logical: u32 = logical.try_into().map_err(|_| EIO)?;
        let in_block = (cur % block_size) as usize;
        let remaining_in_block = block_size as usize - in_block;
        let chunk = core::cmp::min(remaining_in_block, to_read - copied);

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
                // Defence in depth: the cache hands back a slice
                // whose length equals the mount's `block_size`, and
                // `in_block + chunk <= block_size` by construction,
                // so this slice is in-bounds. A bug that violated
                // that would surface as a panic under tests rather
                // than silently scribbling past the cache page.
                debug_assert!(in_block + chunk <= data.len());
                buf[copied..copied + chunk].copy_from_slice(&data[in_block..in_block + chunk]);
            }
            Ok(None) => {
                // Sparse hole: POSIX mandates zero-fill. The caller
                // buffer may contain garbage from a prior dup'd
                // syscall, so we must *actively* zero rather than
                // assuming the buffer started zeroed.
                for b in &mut buf[copied..copied + chunk] {
                    *b = 0;
                }
            }
            Err(WalkError::Io) => return Err(EIO),
            Err(WalkError::Corrupt) => {
                // RFC 0004 §Security: a corrupt pointer means the
                // image is lying to us; fail the read loudly. The
                // force-RO demotion that accompanies `Corrupt` will
                // land with the write path (Workstream E); #561's
                // read-only scope means the damage is already
                // bounded.
                return Err(EIO);
            }
        }
        copied += chunk;
    }

    Ok(copied)
}

/// Build the metadata-forbidden [`MetadataMap`] for `super_` from the
/// parsed superblock + BGDT.
///
/// The forbidden regions are:
///
/// - **Superblock block**: block 1 on 1 KiB volumes, block 0 on
///   ≥ 2 KiB. Matters because a pointer aimed at block 0/1 would
///   overwrite the SB on write and could leak SB contents on read —
///   but more importantly, `absolute_block(..., i=0)` on a 1 KiB
///   volume *is* block 0, which should never appear as a data
///   pointer (data blocks start at `s_first_data_block`). Included
///   for completeness even though the `< s_first_data_block` check
///   in [`Geometry::in_data_range`] already rejects it.
/// - **Block group descriptor table**: the BGDT blocks starting at
///   `s_first_data_block + 1`.
/// - **Per-group**: `bg_block_bitmap`, `bg_inode_bitmap`, and the
///   contiguous inode-table run (`bg_inode_table + inode_table_blocks`).
///
/// The returned map is sorted + coalesced by
/// [`MetadataMap::from_sorted_ranges`]; the caller (`resolve_block`)
/// binary-searches it on every indirect-pointer validation.
///
/// Constructs a fresh map on every call; the cost is `O(groups)`
/// which is negligible for typical ext2 volumes (a 16 GiB / 4 KiB-
/// block fs has ~128 groups). A follow-up that caches the map on
/// [`Ext2Super`] is tracked as an optimisation (RFC 0004 §Indirect-
/// block walker — "memoise the metadata map at mount").
pub(super) fn build_metadata_map(super_: &Arc<Ext2Super>) -> MetadataMap {
    use super::disk::EXT2_GROUP_DESC_SIZE;

    let block_size = super_.block_size;
    let (s_first_data_block, inodes_per_group) = {
        let sb = super_.sb_disk.lock();
        (sb.s_first_data_block, sb.s_inodes_per_group as u64)
    };
    let bgdt_snapshot: alloc::vec::Vec<_> = super_.bgdt.lock().clone();
    let inode_size = super_.inode_size as u64;

    // Raw (unsorted) collection, then sort + coalesce once.
    let mut raw: alloc::vec::Vec<(u32, u32)> = alloc::vec::Vec::new();

    // Superblock block. 1 KiB volumes: block 1. ≥ 2 KiB: block 0. The
    // superblock occupies 1 KiB regardless of block size, so one
    // fs-block is enough.
    let sb_block: u32 = if block_size == 1024 { 1 } else { 0 };
    raw.push((sb_block, sb_block + 1));

    // BGDT. Starts at `s_first_data_block + 1` and spans
    // `ceil(group_count * 32 / block_size)` blocks.
    let groups = bgdt_snapshot.len() as u32;
    if groups > 0 {
        let entries_per_block = block_size / EXT2_GROUP_DESC_SIZE as u32;
        if entries_per_block > 0 {
            let bgdt_blocks = groups.div_ceil(entries_per_block);
            let bgdt_start = s_first_data_block.saturating_add(1);
            if let Some(end) = bgdt_start.checked_add(bgdt_blocks) {
                raw.push((bgdt_start, end));
            }
        }
    }

    // Per-group bitmaps + inode table. The inode-table-block count per
    // group is `ceil(s_inodes_per_group * inode_size / block_size)`.
    let inode_table_bytes = inodes_per_group.saturating_mul(inode_size);
    let inode_table_blocks: u32 = inode_table_bytes
        .div_ceil(block_size as u64)
        .try_into()
        .unwrap_or(u32::MAX);

    for bg in &bgdt_snapshot {
        // Each bitmap occupies exactly one block. (Ext2 caps
        // `blocks_per_group` / `inodes_per_group` at `block_size * 8`
        // precisely so a single-block bitmap covers the whole group.)
        raw.push((bg.bg_block_bitmap, bg.bg_block_bitmap.saturating_add(1)));
        raw.push((bg.bg_inode_bitmap, bg.bg_inode_bitmap.saturating_add(1)));
        if let Some(end) = bg.bg_inode_table.checked_add(inode_table_blocks) {
            raw.push((bg.bg_inode_table, end));
        }
    }

    // Sort by start; drop any zero-length entries; caller coalesces.
    raw.sort_by_key(|&(s, _)| s);
    // `from_sorted_ranges` debug-asserts no overlaps. In practice the
    // SB / BGDT / bitmap / inode-table ranges never overlap on a
    // well-formed image. A malformed image that *does* overlap would
    // trip the debug assert in tests; in release we silently coalesce
    // by dropping later-starting duplicates via `dedup_contiguous`.
    dedup_contiguous(&mut raw);
    MetadataMap::from_sorted_ranges(raw)
}

/// Write up to `buf.len()` bytes into `inode` starting at byte offset
/// `off`, extending the file as needed.
///
/// RFC 0004 §Write extend + §Write Ordering (`docs/RFC/0004-ext2-
/// filesystem-driver.md`) is the normative spec. The pipeline mirrors
/// [`read_file_at`] with three mutation points layered on top:
///
/// 1. **Allocate** any missing indirect-block pointers for the logical
///    blocks in `[off, off+len)` via [`super::balloc::alloc_block`],
///    zero each freshly-allocated pointer block through the buffer
///    cache, and only then **link** the pointer into its parent slot.
///    Ordering matters: a crash between allocate-and-zero and link
///    leaks a block (bitmap says "used", no parent points at it — a
///    fixable `e2fsck` warning). The reverse order could leave a
///    parent pointing at uninitialised bytes that the next reader
///    would interpret as indirect pointers — a structural corruption.
/// 2. **Allocate** the data block itself, `bread` its cache entry,
///    overlay the user bytes, `mark_dirty`, `sync_dirty_buffer`. The
///    data block is linked into its parent (direct slot or indirect
///    leaf) *before* the user bytes are copied — because the block is
///    freshly allocated, nothing else can observe it yet, so zero-on-
///    allocate is the only pre-link invariant we need.
/// 3. **Update** `i_size`, `i_blocks`, `i_mtime`, `i_ctime` on both
///    the driver-owned [`super::inode::Ext2InodeMeta`] and the
///    VFS-level [`crate::fs::vfs::inode::InodeMeta`]; flush the inode
///    slot back to disk. `i_size` update is last in the sequence so a
///    crash between data-block write and size update leaves readers
///    seeing the *old* size (correct, just short), never a size that
///    claims blocks that weren't written.
///
/// # Return value
///
/// - `Ok(n)` where `0 <= n <= buf.len()`. A short write indicates
///   `ENOSPC` or `EFBIG` hit mid-buffer — the bytes already committed
///   remain visible to subsequent reads. The caller (syscall layer)
///   surfaces the partial-write count to userspace; a final `Err(_)`
///   is only returned when *no* bytes were committed.
/// - `Err(EROFS)` — mount is RO (user-requested or feature-forced).
/// - `Err(EISDIR)` — write(2) on a directory.
/// - `Err(EINVAL)` — write(2) on a symlink / device node / FIFO (same
///   dispatch rule as [`read_file_at`]; the open path is expected to
///   bind a driver-specific FileOps at the fd).
/// - `Err(EFBIG)` — `off + len` exceeds the maximum file size the
///   driver can address (past triple-indirect or past `u32::MAX`
///   logical blocks or past `i64::MAX` bytes on a 32-bit-size image).
/// - `Err(ENOSPC)` — no free blocks anywhere *and* no bytes committed
///   yet.
/// - `Err(EIO)` — buffer-cache I/O failure or an image-forged
///   pointer tripped the walker's corruption detector.
pub fn write_file_at(
    inode: &Inode,
    ext2_inode: &super::inode::Ext2Inode,
    buf: &[u8],
    off: u64,
) -> Result<usize, i64> {
    use crate::fs::vfs::inode::InodeKind;

    match inode.kind {
        InodeKind::Reg => {}
        InodeKind::Dir => return Err(EISDIR),
        InodeKind::Link => return Err(EINVAL),
        InodeKind::Chr | InodeKind::Blk | InodeKind::Fifo | InodeKind::Sock => return Err(EINVAL),
    }

    let super_ref = ext2_inode.super_ref.upgrade().ok_or(EIO)?;

    if super_ref.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_ref.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }
    if buf.is_empty() {
        return Ok(0);
    }

    let block_size = super_ref.block_size as u64;
    debug_assert!(block_size > 0, "mount validated block_size != 0");

    // Structural upper bound on file size. Ext2 can address
    // `12 + p + p^2 + p^3` logical blocks where `p = block_size / 4`.
    // That's well under `u64::MAX * block_size` for any legal block
    // size, but we still compute it in `u64` to stay overflow-safe on
    // 64 KiB blocks (`p = 16384`, `p^3 = 2^42`).
    let p64 = block_size / 4;
    let max_logical_blocks: u64 = (EXT2_DIRECT_BLOCKS as u64) + p64 + p64 * p64 + p64 * p64 * p64;
    let max_file_size: u64 = max_logical_blocks.saturating_mul(block_size);

    let off_end = off.checked_add(buf.len() as u64).ok_or(EFBIG)?;
    if off_end > max_file_size {
        return Err(EFBIG);
    }
    // i_size on disk maxes out at 2^63 - 1 even with large_file
    // (s_size + s_size_high is u64 on disk but POSIX `off_t` is `i64`).
    // Reject anything past that.
    if off_end > i64::MAX as u64 {
        return Err(EFBIG);
    }

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

    // Hold the inode's metadata lock write-locked across the whole
    // extend. RFC 0004 §Write extend mandates this against concurrent
    // truncate (truncate will acquire the same lock in Workstream E);
    // it also serialises two racing `write(2)`s on the same inode so
    // their block allocations don't trample each other.
    let mut meta = ext2_inode.meta.write();

    // Hint-group for `alloc_block`: the ext2 "data locality" heuristic
    // is to allocate each new block in the same group as the inode
    // itself. Compute the inode's group once up front.
    let inode_group = if s_inodes_per_group == 0 {
        0
    } else {
        (ext2_inode.ino - 1) / s_inodes_per_group
    };

    let mut copied = 0usize;
    let mut new_i_blocks_bump: u64 = 0;
    let mut last_error: Option<i64> = None;

    while copied < buf.len() {
        let cur = off + copied as u64;
        let logical: u32 = (cur / block_size).try_into().map_err(|_| EFBIG)?;
        let in_block = (cur % block_size) as usize;
        let remaining_in_block = block_size as usize - in_block;
        let chunk = core::cmp::min(remaining_in_block, buf.len() - copied);

        // Ensure the full path to `logical` is allocated. Each new
        // pointer / data block counts toward `new_i_blocks_bump` in
        // 512-byte units.
        let data_block = match ensure_block_allocated(
            &super_ref,
            &geom,
            &md,
            &mut meta.i_block,
            logical,
            inode_group,
            &mut new_i_blocks_bump,
        ) {
            Ok(b) => b,
            Err(e) => {
                // Out-of-space or I/O error part-way through a
                // multi-block write. Preserve the copied count and
                // surface the error to the caller only if nothing has
                // landed yet — otherwise fall through to the metadata
                // flush and report a short write.
                last_error = Some(e);
                break;
            }
        };

        // RMW the data block through the buffer cache: read, overlay,
        // sync. `bread` on a freshly-allocated block still routes
        // through the cache; our own `zero_block` populated the entry
        // above with a zeroed page, so the RMW sees the expected
        // zero prefix + suffix outside our chunk.
        let bh = match super_ref
            .cache
            .bread(super_ref.device_id, data_block as u64)
        {
            Ok(b) => b,
            Err(_) => {
                last_error = Some(EIO);
                break;
            }
        };
        {
            let mut data = bh.data.write();
            debug_assert!(in_block + chunk <= data.len());
            data[in_block..in_block + chunk].copy_from_slice(&buf[copied..copied + chunk]);
        }
        super_ref.cache.mark_dirty(&bh);
        if super_ref.cache.sync_dirty_buffer(&bh).is_err() {
            last_error = Some(EIO);
            break;
        }

        copied += chunk;
    }

    // If we got zero bytes out, surface the error instead of an
    // empty-success return.
    if copied == 0 {
        return Err(last_error.unwrap_or(EIO));
    }

    // Update in-memory metadata. `i_blocks` is in on-disk 512-byte
    // units; `new_i_blocks_bump` was accumulated in those same units.
    let new_size = meta.size.max(off + copied as u64);
    meta.size = new_size;
    meta.i_blocks = meta.i_blocks.saturating_add(new_i_blocks_bump as u32);
    let now = Timespec::now();
    meta.mtime = now.sec as u32;
    meta.ctime = now.sec as u32;

    // Mirror the size / block count / mtime / ctime onto the VFS-layer
    // `Inode::meta` so subsequent `stat(2)` sees the fresh values.
    {
        let mut vfs_meta = inode.meta.write();
        vfs_meta.size = new_size;
        vfs_meta.blocks = meta.i_blocks as u64;
        vfs_meta.mtime = now;
        vfs_meta.ctime = now;
    }

    // Flush the inode slot to disk. This carries the updated `i_size`,
    // `i_blocks`, `i_mtime`, `i_ctime`, and the fresh `i_block[]`
    // pointers. RFC 0004 §Write Ordering: the inode flush is last so a
    // crash leaves readers with at-worst the *old* size — never an
    // `i_size` that claims blocks whose data hasn't hit the device.
    flush_inode_slot(&super_ref, ext2_inode.ino, &meta)?;

    Ok(copied)
}

/// Ensure the logical block `logical` has an allocated data block
/// backing it, creating any missing indirect-block pointers along the
/// way. Returns the absolute data block number.
///
/// Mutates `i_block_mut` in place to install new top-level (direct /
/// indirect / double-indirect / triple-indirect) pointers. Each
/// newly-allocated indirect block is zeroed through the buffer cache
/// before the parent pointer is updated — the RFC 0004 §Write Ordering
/// rule.
///
/// `new_blocks_bump` accumulates the *on-disk 512-byte-unit* cost of
/// every block this call allocated (one fs-block = `block_size / 512`
/// 512-byte units), so the caller can bump `i_blocks` once at the end
/// of the write.
fn ensure_block_allocated(
    super_: &Arc<Ext2Super>,
    geom: &Geometry,
    md: &MetadataMap,
    i_block_mut: &mut [u32; EXT2_N_BLOCKS],
    logical: u32,
    hint_group: u32,
    new_blocks_bump: &mut u64,
) -> Result<u32, i64> {
    let p = geom.ptrs_per_block as u64;
    let direct_limit = EXT2_DIRECT_BLOCKS as u64;
    let single_limit = direct_limit + p;
    let double_limit = single_limit + p * p;
    let triple_limit = double_limit + p * p * p;
    let logical64 = logical as u64;

    let blocks_per_512 = (geom.block_size / 512) as u64;

    if logical64 < direct_limit {
        // Direct: slot `i_block[logical]` *is* the data block pointer.
        let slot = &mut i_block_mut[logical as usize];
        if *slot != 0 {
            validate_existing_pointer(*slot, geom, md)?;
            return Ok(*slot);
        }
        let data_blk = alloc_and_zero_data_block(super_, hint_group, new_blocks_bump)?;
        *slot = data_blk;
        *new_blocks_bump += blocks_per_512;
        Ok(data_blk)
    } else if logical64 < single_limit {
        let idx0 = (logical64 - direct_limit) as u32;
        let ind = ensure_indirect_ptr(
            super_,
            &mut i_block_mut[EXT2_IND_BLOCK],
            geom,
            md,
            hint_group,
            new_blocks_bump,
        )?;
        finish_leaf_slot(super_, ind, idx0, geom, md, hint_group, new_blocks_bump)
    } else if logical64 < double_limit {
        let rel = logical64 - single_limit;
        let idx_outer = (rel / p) as u32;
        let idx_inner = (rel % p) as u32;
        let dind = ensure_indirect_ptr(
            super_,
            &mut i_block_mut[EXT2_DIND_BLOCK],
            geom,
            md,
            hint_group,
            new_blocks_bump,
        )?;
        let ind = ensure_slot_block(
            super_,
            dind,
            idx_outer,
            geom,
            md,
            hint_group,
            new_blocks_bump,
        )?;
        finish_leaf_slot(
            super_,
            ind,
            idx_inner,
            geom,
            md,
            hint_group,
            new_blocks_bump,
        )
    } else if logical64 < triple_limit {
        let rel = logical64 - double_limit;
        let p_sq = p * p;
        let idx_l0 = (rel / p_sq) as u32;
        let rem = rel % p_sq;
        let idx_l1 = (rem / p) as u32;
        let idx_l2 = (rem % p) as u32;
        let tind = ensure_indirect_ptr(
            super_,
            &mut i_block_mut[EXT2_TIND_BLOCK],
            geom,
            md,
            hint_group,
            new_blocks_bump,
        )?;
        let dind = ensure_slot_block(super_, tind, idx_l0, geom, md, hint_group, new_blocks_bump)?;
        let ind = ensure_slot_block(super_, dind, idx_l1, geom, md, hint_group, new_blocks_bump)?;
        finish_leaf_slot(super_, ind, idx_l2, geom, md, hint_group, new_blocks_bump)
    } else {
        Err(EFBIG)
    }
}

/// Validate that `p` — an in-memory pointer we already committed to
/// `i_block[]` or read back out of an indirect block — is a legal
/// data-block pointer (non-zero, in `[s_first_data_block,
/// s_blocks_count)`, not in a metadata range). A malformed pointer
/// here is the same attacker-forged-image confused-deputy vector the
/// read walker guards against.
///
/// Exposed at `pub(super)` so the [`super::aops`] writepage path can
/// reuse the same forgery check before reading or RMW-ing an indirect
/// pointer slot.
pub(super) fn validate_existing_pointer(
    p: u32,
    geom: &Geometry,
    md: &MetadataMap,
) -> Result<(), i64> {
    if !geom.in_data_range(p) || md.contains(p) {
        return Err(EIO);
    }
    Ok(())
}

/// Ensure a top-level indirect slot (single, double, or triple) is
/// populated. If the slot is zero, allocate a fresh indirect block,
/// zero it through the cache, then install the pointer. Returns the
/// absolute indirect-block number.
fn ensure_indirect_ptr(
    super_: &Arc<Ext2Super>,
    slot: &mut u32,
    geom: &Geometry,
    md: &MetadataMap,
    hint_group: u32,
    new_blocks_bump: &mut u64,
) -> Result<u32, i64> {
    if *slot != 0 {
        validate_existing_pointer(*slot, geom, md)?;
        return Ok(*slot);
    }
    let new_blk = alloc_and_zero_pointer_block(super_, hint_group, new_blocks_bump)?;
    *slot = new_blk;
    *new_blocks_bump += (geom.block_size / 512) as u64;
    Ok(new_blk)
}

/// Ensure slot `index` of the pointer block at absolute `parent_blk`
/// holds a non-zero pointer. If it's zero, allocate a new pointer
/// block, zero it, link it into the parent (RMW the parent through
/// the buffer cache), and flush the parent. Returns the absolute
/// pointer-block number now installed at `parent[index]`.
fn ensure_slot_block(
    super_: &Arc<Ext2Super>,
    parent_blk: u32,
    index: u32,
    geom: &Geometry,
    md: &MetadataMap,
    hint_group: u32,
    new_blocks_bump: &mut u64,
) -> Result<u32, i64> {
    let (existing, bh) = read_pointer_slot_raw(super_, parent_blk, index, geom)?;
    if existing != 0 {
        validate_existing_pointer(existing, geom, md)?;
        return Ok(existing);
    }
    // Allocate + zero the child before linking.
    let child = alloc_and_zero_pointer_block(super_, hint_group, new_blocks_bump)?;
    *new_blocks_bump += (geom.block_size / 512) as u64;
    // Link into the parent at slot `index`.
    {
        let mut data = bh.data.write();
        let off = (index as usize) * 4;
        debug_assert!(off + 4 <= data.len());
        data[off..off + 4].copy_from_slice(&child.to_le_bytes());
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(child)
}

/// Leaf path: `parent_blk[index]` holds (or will hold) a data-block
/// pointer. If the slot is zero, allocate + zero a fresh data block,
/// link it into the parent, flush. Returns the absolute data-block
/// number.
fn finish_leaf_slot(
    super_: &Arc<Ext2Super>,
    parent_blk: u32,
    index: u32,
    geom: &Geometry,
    md: &MetadataMap,
    hint_group: u32,
    new_blocks_bump: &mut u64,
) -> Result<u32, i64> {
    let (existing, bh) = read_pointer_slot_raw(super_, parent_blk, index, geom)?;
    if existing != 0 {
        validate_existing_pointer(existing, geom, md)?;
        return Ok(existing);
    }
    let data_blk = alloc_and_zero_data_block(super_, hint_group, new_blocks_bump)?;
    *new_blocks_bump += (geom.block_size / 512) as u64;
    {
        let mut data = bh.data.write();
        let off = (index as usize) * 4;
        debug_assert!(off + 4 <= data.len());
        data[off..off + 4].copy_from_slice(&data_blk.to_le_bytes());
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(data_blk)
}

/// Read the pointer at slot `index` out of the indirect block `abs`
/// and return both the decoded pointer *and* the buffer-cache handle
/// so the caller can RMW the same slot on a miss without a second
/// `bread`.
fn read_pointer_slot_raw(
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
            .expect("pointer slot is exactly 4 bytes");
        u32::from_le_bytes(slot)
    };
    Ok((val, bh))
}

/// Allocate a new block and synchronously zero it through the buffer
/// cache. Used for both newly-allocated indirect pointer blocks and
/// for freshly-allocated data blocks (so a crash between allocate-
/// and-link leaves a zeroed block, never random recycled data from an
/// earlier file's reuse). Returns the absolute block number.
fn alloc_and_zero_pointer_block(
    super_: &Arc<Ext2Super>,
    hint_group: u32,
    _new_blocks_bump: &mut u64,
) -> Result<u32, i64> {
    let blk = alloc_block(super_, Some(hint_group))?;
    zero_block(super_, blk)?;
    Ok(blk)
}

/// Same as [`alloc_and_zero_pointer_block`] but semantically marked
/// "data" — distinguished so a reader of the write path sees that the
/// zero-fill on data blocks is *intentional* (POSIX requires a sparse
/// read of a hole-free-allocated-but-not-yet-written region to return
/// zeros, and a crash after alloc + before the caller's `copy_from`
/// is effectively that case).
fn alloc_and_zero_data_block(
    super_: &Arc<Ext2Super>,
    hint_group: u32,
    _new_blocks_bump: &mut u64,
) -> Result<u32, i64> {
    let blk = alloc_block(super_, Some(hint_group))?;
    zero_block(super_, blk)?;
    Ok(blk)
}

/// Zero the block at absolute `abs` through the per-mount buffer
/// cache and flush it synchronously. A freshly-allocated block's
/// cache entry can contain whatever bytes were previously resident at
/// that physical position on disk — typically zeros on a fresh mkfs,
/// but *not* guaranteed for a block reclaimed from a deleted file.
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
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Flush the in-memory `Ext2InodeMeta` for `ino` back to its on-disk
/// slot. RMW through the buffer cache: read the inode-table block,
/// decode the 128-byte slot, overlay our driver-owned fields, encode
/// back, `mark_dirty`, `sync_dirty_buffer`.
///
/// Intentionally spelled out here rather than factored with `iget` —
/// the writeback surface for the full inode (setattr, truncate, link-
/// count) will land with Workstream E's `write_inode` helper; until
/// then `write_file_at` is the only site that needs to persist the
/// fields it mutates (`i_size`, `i_blocks`, `i_mtime`, `i_ctime`,
/// `i_block[]`). Using a local helper keeps the scope tight.
///
/// Exposed at `pub(super)` so the [`super::aops`] writepage path
/// reuses the same RMW discipline for its own metadata flush.
pub(super) fn flush_inode_slot(
    super_: &Arc<Ext2Super>,
    ino: u32,
    meta: &super::inode::Ext2InodeMeta,
) -> Result<(), i64> {
    let inodes_per_group = {
        let sb = super_.sb_disk.lock();
        sb.s_inodes_per_group
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

    let inode_size = super_.inode_size;
    let block_size = super_.block_size;
    let byte_offset = (index_in_group as u64) * (inode_size as u64);
    let block_in_table = byte_offset / (block_size as u64);
    let offset_in_block = (byte_offset % (block_size as u64)) as usize;
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
        let slot = &mut data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0];
        // Decode the current on-disk slot so we preserve the fields
        // `Ext2InodeMeta` doesn't carry (`i_generation`, `i_file_acl`,
        // `i_osd1`, fragment bits, …) via `DiskInode::encode_to_slot`'s
        // byte-wise preservation guarantee.
        let mut disk = DiskInode::decode(slot);
        apply_meta_to_disk(meta, &mut disk, super_);
        disk.encode_to_slot(slot);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Overlay the fields `Ext2InodeMeta` owns onto a decoded on-disk
/// `DiskInode`, preparing it for re-encode. Large-file size-high
/// handling matches the read path's `Ext2InodeMeta::from_disk`:
/// regular files with `RO_COMPAT_LARGE_FILE` set split `size` across
/// `i_size` + `i_dir_acl_or_size_high`; everything else keeps the
/// low 32 bits only.
fn apply_meta_to_disk(
    meta: &super::inode::Ext2InodeMeta,
    disk: &mut DiskInode,
    super_: &Arc<Ext2Super>,
) {
    let ro_compat = super_.sb_disk.lock().s_feature_ro_compat;
    let large_file = (ro_compat & RO_COMPAT_LARGE_FILE) != 0;
    let is_reg = (meta.mode & 0o170_000) == 0o100_000;

    disk.i_mode = meta.mode;
    if is_reg && large_file {
        disk.i_size = (meta.size & 0xffff_ffff) as u32;
        disk.i_dir_acl_or_size_high = (meta.size >> 32) as u32;
    } else {
        // Clamp to 32 bits — directories and non-large-file regular
        // files can't go past `u32::MAX` bytes. The caller already
        // rejected `off + len > max_file_size`, but guard here too.
        disk.i_size = (meta.size & 0xffff_ffff) as u32;
        // Don't clobber `i_dir_acl` on directories.
    }
    disk.set_uid(meta.uid);
    disk.set_gid(meta.gid);
    disk.i_atime = meta.atime;
    disk.i_ctime = meta.ctime;
    disk.i_mtime = meta.mtime;
    disk.i_dtime = meta.dtime;
    disk.i_links_count = meta.links_count;
    disk.i_blocks = meta.i_blocks;
    disk.i_flags = meta.flags;
    disk.i_block = meta.i_block;
}

/// Merge overlapping / touching ranges in a sorted list into
/// non-overlapping `(start, end_exclusive)` form. Handles the case
/// where two groups' bitmaps happen to touch (shouldn't on a
/// well-formed image, but a sparse-super layout could leave adjacent
/// bitmap blocks) without tripping
/// [`MetadataMap::from_sorted_ranges`]'s no-overlap assert.
fn dedup_contiguous(v: &mut alloc::vec::Vec<(u32, u32)>) {
    if v.len() < 2 {
        return;
    }
    let mut w = 0;
    for r in 1..v.len() {
        let (cur_s, cur_e) = v[w];
        let (s, e) = v[r];
        if s <= cur_e {
            // Overlap or touching: extend.
            v[w] = (cur_s, cur_e.max(e));
        } else {
            w += 1;
            v[w] = (s, e);
        }
    }
    v.truncate(w + 1);
}

#[cfg(test)]
mod tests {
    //! Host-side tests for the pure-logic helpers. The end-to-end
    //! read path is exercised by the QEMU integration test
    //! `kernel/tests/ext2_file_read.rs` which mounts a synthesised
    //! image with known data, hole, and large-file inodes.
    use super::*;

    #[test]
    fn dedup_contiguous_merges_overlap_and_touching() {
        let mut v = alloc::vec![(1u32, 3), (3, 5), (4, 8), (10, 12)];
        dedup_contiguous(&mut v);
        assert_eq!(v, alloc::vec![(1u32, 8), (10, 12)]);
    }

    #[test]
    fn dedup_contiguous_noop_on_disjoint() {
        let mut v = alloc::vec![(1u32, 2), (5, 6), (10, 11)];
        dedup_contiguous(&mut v);
        assert_eq!(v, alloc::vec![(1u32, 2), (5, 6), (10, 11)]);
    }

    #[test]
    fn dedup_contiguous_noop_on_short_input() {
        let mut v: alloc::vec::Vec<(u32, u32)> = alloc::vec::Vec::new();
        dedup_contiguous(&mut v);
        assert!(v.is_empty());
        let mut v = alloc::vec![(1u32, 2)];
        dedup_contiguous(&mut v);
        assert_eq!(v, alloc::vec![(1u32, 2)]);
    }
}
