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

use super::fs::Ext2Super;
use super::indirect::{resolve_block, Geometry, MetadataMap, WalkError};
use crate::fs::vfs::inode::Inode;
use crate::fs::{EIO, EISDIR};

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

    let geom = Geometry::new(
        super_ref.block_size,
        super_ref.sb_disk.s_first_data_block,
        super_ref.sb_disk.s_blocks_count,
    )
    .ok_or(EIO)?;
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
fn build_metadata_map(super_: &Arc<Ext2Super>) -> MetadataMap {
    use super::disk::EXT2_GROUP_DESC_SIZE;

    let block_size = super_.block_size;
    let sb = &super_.sb_disk;
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
    let groups = super_.bgdt.len() as u32;
    if groups > 0 {
        let entries_per_block = block_size / EXT2_GROUP_DESC_SIZE as u32;
        if entries_per_block > 0 {
            let bgdt_blocks = groups.div_ceil(entries_per_block);
            let bgdt_start = sb.s_first_data_block.saturating_add(1);
            if let Some(end) = bgdt_start.checked_add(bgdt_blocks) {
                raw.push((bgdt_start, end));
            }
        }
    }

    // Per-group bitmaps + inode table. The inode-table-block count per
    // group is `ceil(s_inodes_per_group * inode_size / block_size)`.
    let inodes_per_group = sb.s_inodes_per_group as u64;
    let inode_table_bytes = inodes_per_group.saturating_mul(inode_size);
    let inode_table_blocks: u32 = inode_table_bytes
        .div_ceil(block_size as u64)
        .try_into()
        .unwrap_or(u32::MAX);

    for bg in &super_.bgdt {
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
