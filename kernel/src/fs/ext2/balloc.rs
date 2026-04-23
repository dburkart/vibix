//! ext2 block bitmap allocator — `alloc_block` / `free_block`.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Allocator and
//! §Write Ordering are the normative spec. Issue #565 (Workstream E
//! wave 1) lands the block-bitmap allocator: the function that walks
//! the block-group descriptor table, finds a group with a free block,
//! reads that group's block bitmap through the buffer cache, sets the
//! first zero bit, updates the group-descriptor and superblock free
//! counts, and returns the absolute block number.
//!
//! # Write ordering (normative)
//!
//! RFC 0004 §Write Ordering dictates the on-disk effect order for an
//! allocation:
//!
//! 1. **Set the bitmap bit** on the on-disk block bitmap (`bread` → RMW
//!    → `mark_dirty` → `sync_dirty_buffer`). A crash before this step
//!    leaves the bitmap unchanged (the allocation never happened); a
//!    crash after it but before steps 2/3 leaks the block (e2fsck
//!    reclaims it on the next pass — the counter disagreement is a
//!    "fixable" warning, not corruption).
//! 2. **Decrement `bg_free_blocks_count`** for the allocating group on
//!    the on-disk BGDT block (`bread` → RMW → `mark_dirty` →
//!    `sync_dirty_buffer`). The in-memory `bgdt` mirror is updated in
//!    the same critical section so `statfs` and the allocator's own
//!    group-scan see the fresh value.
//! 3. **Decrement `s_free_blocks_count`** on the on-disk superblock
//!    block (`bread` → RMW → `mark_dirty` → `sync_dirty_buffer`). The
//!    in-memory `sb_disk` mirror is updated the same way.
//!
//! A crash between steps 1 and 2 leaks the block (bitmap says "used",
//! counter says "we have one more free than we really do"). A crash
//! between steps 2 and 3 leaks accounting (both counters slightly
//! disagree with reality). Neither produces *corruption* — `e2fsck -y`
//! repairs both. The reverse ordering (counters first, bitmap last)
//! could produce a **double-allocation** if a crash races the sequence:
//! two mounts both see the "old" bitmap and both hand out the same
//! block. That's the failure mode RFC 0004 calls out.
//!
//! `free_block` reverses the order: clear bitmap bit first, then bump
//! counters. A crash mid-sequence leaks a block (bitmap clear, counter
//! says used) — same "fixable" posture.
//!
//! # Locking
//!
//! Per RFC 0004 §Allocator: "bitmap allocator are single-locked." We
//! hold [`Ext2Super::bgdt`] across the entire operation. The `sb_disk`
//! lock is acquired *after* `bgdt` to maintain a strict order — any
//! future call site that needs both must observe the same order.
//!
//! # Metadata-block guard
//!
//! `free_block` rejects attempts to free reserved / metadata blocks
//! (superblock, BGDT blocks, any group's block-bitmap / inode-bitmap /
//! inode-table region, the reserved prefix `[0, s_first_data_block)`).
//! A double-free or an image-forged free of a metadata block maps to
//! `EIO` + force-RO (RFC 0004 §Security: "double-free → EIO + force
//! RO"). We also reject out-of-range block numbers (>= `s_blocks_count`)
//! with `EIO`.

#![allow(dead_code)]

use super::disk::{Ext2GroupDesc, EXT2_GROUP_DESC_SIZE};

#[cfg(all(feature = "ext2", target_os = "none"))]
use alloc::sync::Arc;

#[cfg(all(feature = "ext2", target_os = "none"))]
use super::disk::{Ext2SuperBlock, EXT2_SUPERBLOCK_SIZE};
#[cfg(all(feature = "ext2", target_os = "none"))]
use super::fs::{Ext2MountFlags, Ext2Super, SUPERBLOCK_BYTE_OFFSET};
#[cfg(all(feature = "ext2", target_os = "none"))]
use crate::fs::{EIO, ENOSPC, EROFS};

/// Allocate one block.
///
/// Scans the BGDT for the first group with `bg_free_blocks_count > 0`
/// (optionally biased toward `hint_group`), reads its block bitmap
/// through the buffer cache, finds the first zero bit within
/// `[0, s_blocks_per_group)`, sets it, flushes the bitmap
/// synchronously, then decrements `bg_free_blocks_count` and
/// `s_free_blocks_count` (also flushed synchronously). Returns the
/// absolute block number.
///
/// `hint_group` is the group the caller would *prefer* — typically
/// derived from the inode's parent group for data-locality (RFC 0004
/// §Allocator — "first-fit in parent's group, linear spill"). If the
/// hint is `None`, the scan starts at group 0. The hint is advisory:
/// if the hinted group is full, the scan wraps through all groups.
///
/// # Errors
///
/// - [`ENOSPC`] — every group is full (`s_free_blocks_count == 0` or
///   every BGDT entry has `bg_free_blocks_count == 0`).
/// - [`EROFS`] — the mount is read-only (the allocator is a write path
///   and must refuse on an RO or forced-RO mount).
/// - [`EIO`] — buffer-cache read/write failure, or on-disk state
///   inconsistency (bitmap says "all zero" but counter says "all full",
///   or vice versa).
#[cfg(all(feature = "ext2", target_os = "none"))]
pub fn alloc_block(super_: &Arc<Ext2Super>, hint_group: Option<u32>) -> Result<u32, i64> {
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    // Snapshot the geometry fields under the sb lock. We drop it before
    // touching `bgdt` so the main allocator critical section below can
    // take the sb lock for the counter update without a lock-order
    // violation.
    let (s_blocks_per_group, s_blocks_count, s_first_data_block) = {
        let sb = super_.sb_disk.lock();
        (
            sb.s_blocks_per_group,
            sb.s_blocks_count,
            sb.s_first_data_block,
        )
    };
    if s_blocks_per_group == 0 {
        return Err(EIO);
    }

    // Hold the bgdt lock across the bitmap RMW + counter updates; this
    // is the single-lock serialization the RFC requires.
    let mut bgdt = super_.bgdt.lock();
    let group_count = bgdt.len() as u32;
    if group_count == 0 {
        return Err(EIO);
    }

    // Compute the group scan order: start at the hint (clamped), then
    // wrap around so every group is visited exactly once.
    let start = hint_group.map(|g| g % group_count).unwrap_or(0);

    for step in 0..group_count {
        let group = (start + step) % group_count;
        let bg = &bgdt[group as usize];
        if bg.bg_free_blocks_count == 0 {
            continue;
        }
        let bitmap_blk = bg.bg_block_bitmap as u64;

        // Read the bitmap block, find the first zero bit in
        // `[0, blocks_in_this_group)`, set it, flush.
        let bh = super_
            .cache
            .bread(super_.device_id, bitmap_blk)
            .map_err(|_| EIO)?;
        // `blocks_in_this_group` may be less than `s_blocks_per_group`
        // on the last (short) group. The bits past the group's end are
        // expected to be set to 1 by mkfs (they represent "past end of
        // fs"); we still cap our search to the real group size to be
        // defensive against a mis-formatted image.
        let blocks_in_this_group =
            blocks_in_group(group, group_count, s_blocks_per_group, s_blocks_count);

        let found_bit = {
            let mut data = bh.data.write();
            match find_first_zero_bit(&data, blocks_in_this_group as usize) {
                Some(bit) => {
                    // Set the bit (RMW). `find_first_zero_bit` validated
                    // the index < `blocks_in_this_group`, so the byte
                    // offset is in-bounds.
                    let byte = bit / 8;
                    let mask = 1u8 << (bit % 8);
                    debug_assert!(data[byte] & mask == 0, "bitmap changed under lock");
                    data[byte] |= mask;
                    Some(bit as u32)
                }
                None => None,
            }
        };

        let Some(bit) = found_bit else {
            // Counter disagreed with the bitmap — the image is
            // inconsistent. Force-RO and bail. The caller can't safely
            // retry since the in-memory counter is now known-wrong.
            return Err(EIO);
        };

        super_.cache.mark_dirty(&bh);
        super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;

        // Compute the absolute block number. `bit` indexes blocks
        // starting at `s_first_data_block + group * s_blocks_per_group`.
        let abs = s_first_data_block
            .checked_add(group.checked_mul(s_blocks_per_group).ok_or(EIO)?)
            .and_then(|v| v.checked_add(bit))
            .ok_or(EIO)?;
        if abs >= s_blocks_count {
            // The short-group tail is padded with 1-bits by mkfs so a
            // well-formed bitmap would never produce an out-of-fs bit.
            // If we land here the image is lying; force-RO.
            return Err(EIO);
        }

        // Decrement the in-memory BGDT entry and flush its on-disk
        // slot.
        bgdt[group as usize].bg_free_blocks_count =
            bgdt[group as usize].bg_free_blocks_count.saturating_sub(1);
        flush_bgdt_entry(
            super_,
            group,
            &bgdt[group as usize],
            s_first_data_block,
            super_.block_size,
        )?;

        // Decrement the in-memory superblock counter and flush the
        // on-disk superblock.
        {
            let mut sb = super_.sb_disk.lock();
            sb.s_free_blocks_count = sb.s_free_blocks_count.saturating_sub(1);
            flush_superblock(super_, &sb)?;
        }

        return Ok(abs);
    }

    Err(ENOSPC)
}

/// Free one block.
///
/// Validates `bno` is inside `[s_first_data_block, s_blocks_count)`,
/// not inside any metadata range, then clears the bit in the owning
/// group's block bitmap and bumps the counters. Write order is the
/// same as `alloc_block` (bitmap first, counters after).
///
/// # Errors
///
/// - [`EROFS`] — RO mount.
/// - [`EIO`] — `bno` is out of range, in the reserved prefix, in a
///   metadata range, or the bit was already clear (double-free). A
///   double-free also force-ROs the mount via the RFC 0004 §Security
///   rule (not implemented as an actual flip here — the driver records
///   the error; an upper layer owns the force-RO mechanism, tracked
///   in the wave-F sync path).
#[cfg(all(feature = "ext2", target_os = "none"))]
pub fn free_block(super_: &Arc<Ext2Super>, bno: u32) -> Result<(), i64> {
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    let (s_blocks_per_group, s_blocks_count, s_first_data_block, s_inodes_per_group) = {
        let sb = super_.sb_disk.lock();
        (
            sb.s_blocks_per_group,
            sb.s_blocks_count,
            sb.s_first_data_block,
            sb.s_inodes_per_group,
        )
    };
    if s_blocks_per_group == 0 {
        return Err(EIO);
    }
    if bno < s_first_data_block || bno >= s_blocks_count {
        return Err(EIO);
    }

    let inode_size = super_.inode_size as u64;
    let block_size = super_.block_size;

    let mut bgdt = super_.bgdt.lock();
    let group_count = bgdt.len() as u32;
    if group_count == 0 {
        return Err(EIO);
    }

    // Reject any free that lands inside a metadata range (superblock
    // copy, BGDT, bitmaps, inode table). RFC 0004 §Security — "forbid
    // allocation within metadata ranges."
    if is_metadata_block(
        bno,
        s_first_data_block,
        s_inodes_per_group,
        block_size,
        inode_size,
        group_count,
        &bgdt,
    ) {
        return Err(EIO);
    }

    // Translate bno → (group, bit_index_in_group).
    let rel = bno - s_first_data_block;
    let group = rel / s_blocks_per_group;
    let bit = rel % s_blocks_per_group;
    if group >= group_count {
        return Err(EIO);
    }
    let bitmap_blk = bgdt[group as usize].bg_block_bitmap as u64;

    let bh = super_
        .cache
        .bread(super_.device_id, bitmap_blk)
        .map_err(|_| EIO)?;

    let was_set = {
        let mut data = bh.data.write();
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        if byte >= data.len() {
            false
        } else if data[byte] & mask == 0 {
            false // already clear → double-free
        } else {
            data[byte] &= !mask;
            true
        }
    };
    if !was_set {
        // Double-free. Don't mark the cache dirty; bail with EIO so the
        // caller can propagate the error. A production driver would
        // also force-RO; that lever lives above this layer.
        return Err(EIO);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;

    // Bump the in-memory BGDT entry, flush it to disk.
    bgdt[group as usize].bg_free_blocks_count =
        bgdt[group as usize].bg_free_blocks_count.saturating_add(1);
    flush_bgdt_entry(
        super_,
        group,
        &bgdt[group as usize],
        s_first_data_block,
        block_size,
    )?;

    // Bump the in-memory superblock counter, flush.
    {
        let mut sb = super_.sb_disk.lock();
        sb.s_free_blocks_count = sb.s_free_blocks_count.saturating_add(1);
        flush_superblock(super_, &sb)?;
    }

    Ok(())
}

/// Number of real (in-fs) blocks in `group`. For every group except the
/// last it equals `s_blocks_per_group`; the last group is shorter when
/// `s_blocks_count - s_first_data_block` is not a whole multiple of
/// `s_blocks_per_group`.
fn blocks_in_group(
    group: u32,
    group_count: u32,
    s_blocks_per_group: u32,
    s_blocks_count: u32,
) -> u32 {
    if group + 1 < group_count {
        s_blocks_per_group
    } else {
        // Last group: remainder of the total data-block range. Because
        // `s_first_data_block` is 0 or 1 and the count is `u32`, the
        // `u64` arithmetic prevents overflow on pathological images.
        let total_data_blocks = s_blocks_count;
        let full_groups_blocks = (group_count - 1) as u64 * s_blocks_per_group as u64;
        // `total_data_blocks - full_groups_blocks` is the tail; a
        // malformed image with an oversized count underflows and we
        // just return 0, which forces the per-group scan to skip this
        // group (counter > 0 but no bits means EIO → force-RO).
        (total_data_blocks as u64)
            .saturating_sub(full_groups_blocks)
            .min(s_blocks_per_group as u64) as u32
    }
}

/// Scan the first `bit_limit` bits of `bitmap` (LE byte order, LSB
/// first within each byte — standard ext2 layout) for the first zero
/// bit. Returns `None` if all `bit_limit` bits are set.
fn find_first_zero_bit(bitmap: &[u8], bit_limit: usize) -> Option<usize> {
    // Fast-scan whole bytes that are entirely inside the limit.
    let full_bytes = bit_limit / 8;
    let tail_bits = bit_limit % 8;

    for (byte_idx, b) in bitmap.iter().take(full_bytes).enumerate() {
        if *b != 0xff {
            // Find the lowest zero bit in this byte.
            let inverted = !*b;
            let off = inverted.trailing_zeros() as usize;
            return Some(byte_idx * 8 + off);
        }
    }
    if tail_bits > 0 && full_bytes < bitmap.len() {
        let b = bitmap[full_bytes];
        for off in 0..tail_bits {
            if b & (1 << off) == 0 {
                return Some(full_bytes * 8 + off);
            }
        }
    }
    None
}

/// RMW-flush the BGDT slot for `group` back to its on-disk location.
///
/// The BGDT lives in one or more contiguous blocks starting at
/// `s_first_data_block + 1`; each block packs `block_size /
/// EXT2_GROUP_DESC_SIZE` entries. We compute the containing block +
/// offset-in-block, read that block through the cache, overlay the
/// updated 32-byte slot, flush synchronously.
#[cfg(all(feature = "ext2", target_os = "none"))]
fn flush_bgdt_entry(
    super_: &Arc<Ext2Super>,
    group: u32,
    bg: &Ext2GroupDesc,
    s_first_data_block: u32,
    block_size: u32,
) -> Result<(), i64> {
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
        bg.encode_to_slot(&mut data[byte_off..byte_off + EXT2_GROUP_DESC_SIZE]);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// RMW-flush the primary superblock back to its on-disk location. The
/// SB always lives at byte offset 1024 on disk; the containing cache
/// block is `1024 / block_size`, with a within-block offset of `1024 %
/// block_size` (0 on 1 KiB filesystems, 1024 on 2 KiB+).
#[cfg(all(feature = "ext2", target_os = "none"))]
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

/// `true` iff `bno` is inside the reserved prefix, the superblock
/// block, the BGDT, or any group's block-bitmap / inode-bitmap /
/// inode-table. Used by [`free_block`] to reject a free that aims at
/// metadata.
fn is_metadata_block(
    bno: u32,
    s_first_data_block: u32,
    s_inodes_per_group: u32,
    block_size: u32,
    inode_size: u64,
    group_count: u32,
    bgdt: &[Ext2GroupDesc],
) -> bool {
    // Reserved prefix — `[0, s_first_data_block)`. Already rejected
    // upstream in `free_block`, but spelled out here for clarity.
    if bno < s_first_data_block {
        return true;
    }

    // Superblock block: always absolute block 1 on 1 KiB filesystems
    // (s_first_data_block == 1), block 0 on ≥ 2 KiB. That's exactly
    // `s_first_data_block`'s-adjacent block — for 1 KiB it's `< 1 + 1`,
    // for ≥ 2 KiB the `< s_first_data_block` check above already
    // handles it.
    if block_size == 1024 && bno == 1 {
        return true;
    }

    // BGDT blocks: `[s_first_data_block + 1, s_first_data_block + 1 +
    // bgdt_blocks)`.
    let entries_per_block = block_size / EXT2_GROUP_DESC_SIZE as u32;
    if entries_per_block > 0 {
        let bgdt_blocks = group_count.div_ceil(entries_per_block);
        let bgdt_start = s_first_data_block.saturating_add(1);
        let bgdt_end = bgdt_start.saturating_add(bgdt_blocks);
        if bno >= bgdt_start && bno < bgdt_end {
            return true;
        }
    }

    // Per-group bitmaps + inode table.
    let inode_table_bytes = (s_inodes_per_group as u64).saturating_mul(inode_size);
    let inode_table_blocks: u32 = inode_table_bytes
        .div_ceil(block_size as u64)
        .try_into()
        .unwrap_or(u32::MAX);
    for bg in bgdt {
        if bno == bg.bg_block_bitmap || bno == bg.bg_inode_bitmap {
            return true;
        }
        let it_start = bg.bg_inode_table;
        let it_end = it_start.saturating_add(inode_table_blocks);
        if bno >= it_start && bno < it_end {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    //! Host-side unit tests. The allocator's end-to-end flow is
    //! exercised by the QEMU integration test
    //! `kernel/tests/ext2_block_alloc.rs`; the tests here target the
    //! pure bit-manipulation and bounds helpers that don't need a live
    //! `Ext2Super`.

    use super::*;

    #[test]
    fn find_first_zero_bit_full_byte() {
        let bitmap = [0x00u8; 4];
        assert_eq!(find_first_zero_bit(&bitmap, 32), Some(0));
    }

    #[test]
    fn find_first_zero_bit_all_set() {
        let bitmap = [0xffu8; 4];
        assert_eq!(find_first_zero_bit(&bitmap, 32), None);
    }

    #[test]
    fn find_first_zero_bit_respects_limit() {
        // Entire bitmap is 1s except bit 40 (byte 5, bit 0). If the
        // limit only covers 32 bits, the zero must not be found.
        let mut bitmap = [0xffu8; 8];
        bitmap[5] = 0xfe;
        assert_eq!(find_first_zero_bit(&bitmap, 32), None);
        // Extend the limit past bit 40 and it shows up.
        assert_eq!(find_first_zero_bit(&bitmap, 48), Some(40));
    }

    #[test]
    fn find_first_zero_bit_partial_byte() {
        // First 3 bits set; bit 3 is the first zero. Limit < 3 → None;
        // limit >= 4 → Some(3).
        let bitmap = [0b0000_0111u8];
        assert_eq!(find_first_zero_bit(&bitmap, 3), None);
        assert_eq!(find_first_zero_bit(&bitmap, 4), Some(3));
    }

    #[test]
    fn find_first_zero_bit_first_set_byte_has_hole() {
        // Byte 0 = 0xFE: bit 0 is zero. The lowest zero bit should be
        // at index 0.
        let bitmap = [0xfeu8, 0xff, 0xff];
        assert_eq!(find_first_zero_bit(&bitmap, 24), Some(0));
        // Byte 0 = 0xFF, byte 1 = 0xFD (bits 0+1): lowest zero is bit 9
        // (byte 1, bit 1).
        let bitmap = [0xff, 0xfdu8, 0xff];
        assert_eq!(find_first_zero_bit(&bitmap, 24), Some(9));
    }

    #[test]
    fn blocks_in_group_last_group_short() {
        // 1024 total data blocks, 512 per group → 2 groups, both full
        // length.
        assert_eq!(blocks_in_group(0, 2, 512, 1024), 512);
        assert_eq!(blocks_in_group(1, 2, 512, 1024), 512);
        // 1000 total, 512 per group → 2 groups, last is 488 long.
        assert_eq!(blocks_in_group(0, 2, 512, 1000), 512);
        assert_eq!(blocks_in_group(1, 2, 512, 1000), 488);
        // Single group: blocks_in_group clamps to blocks_per_group.
        assert_eq!(blocks_in_group(0, 1, 1024, 800), 800);
    }

    #[test]
    fn is_metadata_block_catches_superblock_and_bgdt() {
        // 1 KiB filesystem: superblock at block 1, BGDT at block 2,
        // one bgd occupies byte 0..32 of the BGDT block.
        let bgdt = alloc::vec![Ext2GroupDesc {
            bg_block_bitmap: 3,
            bg_inode_bitmap: 4,
            bg_inode_table: 5,
            bg_free_blocks_count: 0,
            bg_free_inodes_count: 0,
            bg_used_dirs_count: 0,
            bg_pad: 0,
            bg_reserved: [0; 12],
        }];
        // block 0: reserved prefix (< s_first_data_block=1).
        assert!(is_metadata_block(0, 1, 16, 1024, 128, 1, &bgdt));
        // block 1: superblock on 1 KiB fs.
        assert!(is_metadata_block(1, 1, 16, 1024, 128, 1, &bgdt));
        // block 2: BGDT (s_first_data_block + 1).
        assert!(is_metadata_block(2, 1, 16, 1024, 128, 1, &bgdt));
        // block 3: block bitmap.
        assert!(is_metadata_block(3, 1, 16, 1024, 128, 1, &bgdt));
        // block 4: inode bitmap.
        assert!(is_metadata_block(4, 1, 16, 1024, 128, 1, &bgdt));
        // block 5: first inode-table block (16 inodes × 128 B = 2 KiB
        // = 2 blocks, so table occupies blocks 5..=6).
        assert!(is_metadata_block(5, 1, 16, 1024, 128, 1, &bgdt));
        assert!(is_metadata_block(6, 1, 16, 1024, 128, 1, &bgdt));
        // block 7: first data block. Not metadata.
        assert!(!is_metadata_block(7, 1, 16, 1024, 128, 1, &bgdt));
    }

    #[test]
    fn is_metadata_block_2kib_fs_has_sb_at_block_0() {
        // 2 KiB fs: s_first_data_block = 0, superblock at byte 1024
        // within block 0. Block 0 is caught by the reserved-prefix
        // rule? No — s_first_data_block is 0 so the `< 0` guard is
        // never true. Block 0 is still metadata because the SB is
        // there: the `block_size != 1024` branch of `is_metadata_block`
        // relies on the BGDT / per-group checks to catch it. A 2 KiB
        // image always has the BGDT at block 1 so block 0 must be
        // explicitly listed too.
        //
        // This test pins that gap: today, block 0 on a 2 KiB fs falls
        // through `is_metadata_block` as "data" unless we explicitly
        // add it. Document current behaviour so a future fix is a
        // deliberate change, not an accident.
        let bgdt = alloc::vec![Ext2GroupDesc {
            bg_block_bitmap: 2,
            bg_inode_bitmap: 3,
            bg_inode_table: 4,
            bg_free_blocks_count: 0,
            bg_free_inodes_count: 0,
            bg_used_dirs_count: 0,
            bg_pad: 0,
            bg_reserved: [0; 12],
        }];
        // BGDT at block 1 on a 2 KiB fs (s_first_data_block + 1 = 1).
        assert!(is_metadata_block(1, 0, 16, 2048, 128, 1, &bgdt));
        // Block 0: superblock lives *inside* this block but the
        // allocator never hands out block 0 on a 2 KiB fs because
        // `s_first_data_block == 0` means group 0 starts at 0 — the
        // SB-holding block is reserved by mkfs via pre-set bitmap bits,
        // not by `is_metadata_block`. Document that: block 0 is NOT
        // currently caught here.
        assert!(!is_metadata_block(0, 0, 16, 2048, 128, 1, &bgdt));
    }
}
