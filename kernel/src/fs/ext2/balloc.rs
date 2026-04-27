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
use super::fs::{Ext2Super, SUPERBLOCK_BYTE_OFFSET};
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
    if !super_.is_writable() {
        return Err(EROFS);
    }

    // Snapshot the geometry fields under the sb lock. We drop it before
    // touching `bgdt` so the main allocator critical section below can
    // take the sb lock for the counter update without a lock-order
    // violation.
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
    let inode_size = super_.inode_size as u64;
    let block_size = super_.block_size;

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
        let blocks_in_this_group = blocks_in_group(
            group,
            group_count,
            s_blocks_per_group,
            s_blocks_count,
            s_first_data_block,
        );

        let found_bit = {
            let mut data = bh.data.write();
            // Search the bitmap for a zero bit that *also* doesn't fall
            // inside any metadata range (#617 item 2: a corrupted image
            // with a clear bit over metadata must not be handed out).
            // `find_first_zero_bit_skipping` calls the predicate to
            // gate each candidate; a `false` answer marks that bit
            // implicitly forbidden so the search advances.
            let mut bit_opt: Option<u32> = None;
            let mut start_bit = 0usize;
            while let Some(bit) =
                find_first_zero_bit(&data, blocks_in_this_group as usize, start_bit)
            {
                let abs = match s_first_data_block
                    .checked_add(group.checked_mul(s_blocks_per_group).ok_or(EIO)?)
                    .and_then(|v| v.checked_add(bit as u32))
                {
                    Some(v) => v,
                    None => return Err(EIO),
                };
                if is_metadata_block(
                    abs,
                    s_first_data_block,
                    s_blocks_per_group,
                    s_inodes_per_group,
                    block_size,
                    inode_size,
                    group_count,
                    &bgdt,
                ) {
                    // The on-disk bitmap is lying about a metadata
                    // block being free. Skip it (don't mutate the
                    // bitmap — leaving the bit clear preserves the
                    // image's existing state for fsck) and continue.
                    start_bit = bit + 1;
                    continue;
                }
                // Set the bit (RMW). `find_first_zero_bit` validated
                // the index < `blocks_in_this_group`, so the byte
                // offset is in-bounds.
                let byte = bit / 8;
                let mask = 1u8 << (bit % 8);
                debug_assert!(data[byte] & mask == 0, "bitmap changed under lock");
                data[byte] |= mask;
                bit_opt = Some(bit as u32);
                break;
            }
            bit_opt
        };

        let Some(bit) = found_bit else {
            // Counter disagreed with the bitmap — the image is
            // inconsistent. Force-RO and bail. The caller can't safely
            // retry since the in-memory counter is now known-wrong.
            super_.force_ro();
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
            super_.force_ro();
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
    if !super_.is_writable() {
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
        s_blocks_per_group,
        s_inodes_per_group,
        block_size,
        inode_size,
        group_count,
        &bgdt,
    ) {
        // Force-RO: an attempt to free a metadata block is either a
        // driver bug or a corrupt request from above; either way the
        // image's integrity is now suspect (#617 item 3).
        super_.force_ro();
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
        // Double-free. Don't mark the cache dirty; trip the runtime
        // force-RO latch so subsequent allocator calls refuse with
        // EROFS (RFC 0004 §Security: "double-free → EIO + force RO").
        // The caller still gets EIO for this call so the failure is
        // visible.
        super_.force_ro();
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
///
/// Note: the total data-block range is `s_blocks_count - s_first_data_block`,
/// not `s_blocks_count`. On 1 KiB ext2 (`s_first_data_block == 1`) the
/// final group is one block shorter than the naive computation suggests
/// — a full filesystem would otherwise surface as `EIO` instead of
/// `ENOSPC` (#617 item 4).
fn blocks_in_group(
    group: u32,
    group_count: u32,
    s_blocks_per_group: u32,
    s_blocks_count: u32,
    s_first_data_block: u32,
) -> u32 {
    if group + 1 < group_count {
        s_blocks_per_group
    } else {
        // Last group: remainder of the total data-block range,
        // measured *after* the reserved prefix `[0, s_first_data_block)`.
        // The `u64` arithmetic prevents overflow on pathological
        // images.
        let total_data_blocks = s_blocks_count.saturating_sub(s_first_data_block) as u64;
        let full_groups_blocks = (group_count - 1) as u64 * s_blocks_per_group as u64;
        // `total_data_blocks - full_groups_blocks` is the tail; a
        // malformed image with an oversized count underflows and we
        // just return 0, which forces the per-group scan to skip this
        // group (counter > 0 but no bits means EIO → force-RO).
        total_data_blocks
            .saturating_sub(full_groups_blocks)
            .min(s_blocks_per_group as u64) as u32
    }
}

/// Scan bits `[start_bit, bit_limit)` of `bitmap` (LE byte order, LSB
/// first within each byte — standard ext2 layout) for the first zero
/// bit. Returns `None` if every bit in that range is set.
///
/// `start_bit` lets the allocator's metadata-skip loop resume the search
/// past a forbidden candidate (#617 item 2) without rescanning bits it
/// already classified.
fn find_first_zero_bit(bitmap: &[u8], bit_limit: usize, start_bit: usize) -> Option<usize> {
    if start_bit >= bit_limit {
        return None;
    }
    // Examine the partial first byte (the one containing `start_bit`)
    // bit-by-bit so we honour `start_bit % 8 != 0`.
    let first_byte = start_bit / 8;
    let first_byte_offset = start_bit % 8;
    if first_byte < bitmap.len() {
        let b = bitmap[first_byte];
        let byte_end = ((first_byte + 1) * 8).min(bit_limit);
        for off in first_byte_offset..(byte_end - first_byte * 8) {
            if b & (1 << off) == 0 {
                return Some(first_byte * 8 + off);
            }
        }
    }

    // Whole-byte fast scan past the partial first byte, but only over
    // bytes fully inside the limit.
    let full_bytes = bit_limit / 8;
    let tail_bits = bit_limit % 8;
    for byte_idx in (first_byte + 1)..full_bytes {
        let b = bitmap[byte_idx];
        if b != 0xff {
            let inverted = !b;
            let off = inverted.trailing_zeros() as usize;
            return Some(byte_idx * 8 + off);
        }
    }
    if tail_bits > 0 && full_bytes < bitmap.len() && full_bytes > first_byte {
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

/// `true` iff `bno` is inside the reserved prefix, the primary or any
/// **backup** superblock / BGDT, or any group's block-bitmap /
/// inode-bitmap / inode-table.
///
/// Used by both [`free_block`] (to reject frees that aim at metadata)
/// and [`alloc_block`] (#617 item 2: don't trust the on-disk bitmap;
/// re-check candidates against the same map so a corrupt image can't
/// hand metadata out).
///
/// Backup-SB/BGDT coverage (#617 item 1): on every group `g`, the first
/// block of the group is `s_first_data_block + g * s_blocks_per_group`.
/// On non-`sparse_super` filesystems (and on group 0 / 1 / powers of
/// 3, 5, 7 on `sparse_super` ones) that block holds a backup
/// superblock and the next `bgdt_blocks` blocks hold a backup group
/// descriptor table. We forbid the SB+BGDT range in **every** group
/// unconditionally — over-protection is harmless (those backup blocks
/// must never be allocated as data anyway), and the simple sweep
/// avoids replicating the `RO_COMPAT_SPARSE_SUPER` placement table.
///
/// Block 0 on ≥ 2 KiB filesystems: the primary SB lives inside block 0
/// (`s_first_data_block == 0`, SB at byte 1024 inside that block), so
/// block 0 must be forbidden explicitly — the `< s_first_data_block`
/// guard alone doesn't catch it.
fn is_metadata_block(
    bno: u32,
    s_first_data_block: u32,
    s_blocks_per_group: u32,
    s_inodes_per_group: u32,
    block_size: u32,
    inode_size: u64,
    group_count: u32,
    bgdt: &[Ext2GroupDesc],
) -> bool {
    // Reserved prefix — `[0, s_first_data_block)`. On 1 KiB filesystems
    // this catches block 0 (the boot block).
    if bno < s_first_data_block {
        return true;
    }

    // Block 0 on ≥ 2 KiB filesystems holds the primary superblock
    // (#617 item 1). `s_first_data_block` is 0 there so the guard
    // above doesn't catch it.
    if block_size != 1024 && bno == 0 {
        return true;
    }

    // Per-group SB + BGDT copies. Iterate every group: the first block
    // of group `g` is `s_first_data_block + g * s_blocks_per_group`. On
    // group 0 this is also the primary SB; on later groups it's a
    // backup. The next `bgdt_blocks` blocks hold the BGDT (or its
    // backup). We forbid the whole `[group_start, group_start + 1 +
    // bgdt_blocks)` range — see the function-level note on backup
    // coverage.
    let entries_per_block = block_size / EXT2_GROUP_DESC_SIZE as u32;
    let bgdt_blocks = if entries_per_block == 0 {
        0
    } else {
        group_count.div_ceil(entries_per_block)
    };
    if s_blocks_per_group > 0 {
        for g in 0..group_count {
            let group_start = match (g as u64)
                .checked_mul(s_blocks_per_group as u64)
                .and_then(|v| v.checked_add(s_first_data_block as u64))
            {
                Some(v) if v <= u32::MAX as u64 => v as u32,
                _ => continue,
            };
            // SB block (group 0 primary, others backup).
            if bno == group_start {
                return true;
            }
            // BGDT (primary or backup) sits immediately after.
            let bgdt_start = group_start.saturating_add(1);
            let bgdt_end = bgdt_start.saturating_add(bgdt_blocks);
            if bno >= bgdt_start && bno < bgdt_end {
                return true;
            }
        }
    }

    // Per-group bitmaps + inode table (parsed from the live BGDT
    // entries — those are authoritative for placement when
    // `resize_inode` or `meta_bg` shuffles the inode table).
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
        assert_eq!(find_first_zero_bit(&bitmap, 32, 0), Some(0));
    }

    #[test]
    fn find_first_zero_bit_all_set() {
        let bitmap = [0xffu8; 4];
        assert_eq!(find_first_zero_bit(&bitmap, 32, 0), None);
    }

    #[test]
    fn find_first_zero_bit_respects_limit() {
        // Entire bitmap is 1s except bit 40 (byte 5, bit 0). If the
        // limit only covers 32 bits, the zero must not be found.
        let mut bitmap = [0xffu8; 8];
        bitmap[5] = 0xfe;
        assert_eq!(find_first_zero_bit(&bitmap, 32, 0), None);
        // Extend the limit past bit 40 and it shows up.
        assert_eq!(find_first_zero_bit(&bitmap, 48, 0), Some(40));
    }

    #[test]
    fn find_first_zero_bit_partial_byte() {
        // First 3 bits set; bit 3 is the first zero. Limit < 3 → None;
        // limit >= 4 → Some(3).
        let bitmap = [0b0000_0111u8];
        assert_eq!(find_first_zero_bit(&bitmap, 3, 0), None);
        assert_eq!(find_first_zero_bit(&bitmap, 4, 0), Some(3));
    }

    #[test]
    fn find_first_zero_bit_first_set_byte_has_hole() {
        // Byte 0 = 0xFE: bit 0 is zero. The lowest zero bit should be
        // at index 0.
        let bitmap = [0xfeu8, 0xff, 0xff];
        assert_eq!(find_first_zero_bit(&bitmap, 24, 0), Some(0));
        // Byte 0 = 0xFF, byte 1 = 0xFD (bits 0+1): lowest zero is bit 9
        // (byte 1, bit 1).
        let bitmap = [0xff, 0xfdu8, 0xff];
        assert_eq!(find_first_zero_bit(&bitmap, 24, 0), Some(9));
    }

    #[test]
    fn find_first_zero_bit_skips_to_start() {
        // All zeros. Without start_bit we'd return 0; with start_bit=5
        // we should return 5. With start_bit=10 (past limit=8) → None.
        let bitmap = [0x00u8, 0x00];
        assert_eq!(find_first_zero_bit(&bitmap, 16, 0), Some(0));
        assert_eq!(find_first_zero_bit(&bitmap, 16, 5), Some(5));
        assert_eq!(find_first_zero_bit(&bitmap, 8, 10), None);

        // Mixed: bit 3 and bit 11 are zero, rest are set. start_bit=4
        // skips the first hole and finds bit 11.
        let bitmap = [0b1111_0111u8, 0b1111_0111u8];
        assert_eq!(find_first_zero_bit(&bitmap, 16, 0), Some(3));
        assert_eq!(find_first_zero_bit(&bitmap, 16, 4), Some(11));
    }

    #[test]
    fn blocks_in_group_last_group_short() {
        // 1024 total data blocks (s_first_data_block=0), 512 per group
        // → 2 groups, both full length.
        assert_eq!(blocks_in_group(0, 2, 512, 1024, 0), 512);
        assert_eq!(blocks_in_group(1, 2, 512, 1024, 0), 512);
        // 1000 total, 512 per group, s_first_data_block=0 → 2 groups,
        // last is 488 long.
        assert_eq!(blocks_in_group(0, 2, 512, 1000, 0), 512);
        assert_eq!(blocks_in_group(1, 2, 512, 1000, 0), 488);
        // Single group: blocks_in_group clamps to blocks_per_group.
        assert_eq!(blocks_in_group(0, 1, 1024, 800, 0), 800);
    }

    #[test]
    fn blocks_in_group_subtracts_first_data_block() {
        // 1 KiB ext2: s_blocks_count = 1024, s_blocks_per_group = 512,
        // s_first_data_block = 1. Total data blocks = 1023, so two
        // groups: 512 + 511 — NOT 512 + 512 (#617 item 4). Without the
        // fix the last group would report 512 and the allocator would
        // happily try to allocate a block past the end of the fs.
        assert_eq!(blocks_in_group(0, 2, 512, 1024, 1), 512);
        assert_eq!(blocks_in_group(1, 2, 512, 1024, 1), 511);
    }

    #[test]
    fn is_metadata_block_catches_superblock_and_bgdt() {
        // 1 KiB filesystem, 1 group: superblock at block 1, BGDT at
        // block 2, one bgd entry occupies byte 0..32 of the BGDT block.
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
        // s_blocks_per_group=8 here (small group; the absolute numbers
        // we test don't depend on its exact value, only that the
        // group_start arithmetic works).
        let spg = 1024;
        // block 0: reserved prefix (< s_first_data_block=1).
        assert!(is_metadata_block(0, 1, spg, 16, 1024, 128, 1, &bgdt));
        // block 1: superblock on 1 KiB fs (group 0 SB).
        assert!(is_metadata_block(1, 1, spg, 16, 1024, 128, 1, &bgdt));
        // block 2: BGDT (group_start + 1).
        assert!(is_metadata_block(2, 1, spg, 16, 1024, 128, 1, &bgdt));
        // block 3: block bitmap.
        assert!(is_metadata_block(3, 1, spg, 16, 1024, 128, 1, &bgdt));
        // block 4: inode bitmap.
        assert!(is_metadata_block(4, 1, spg, 16, 1024, 128, 1, &bgdt));
        // block 5: first inode-table block (16 inodes × 128 B = 2 KiB
        // = 2 blocks, so table occupies blocks 5..=6).
        assert!(is_metadata_block(5, 1, spg, 16, 1024, 128, 1, &bgdt));
        assert!(is_metadata_block(6, 1, spg, 16, 1024, 128, 1, &bgdt));
        // block 7: first data block. Not metadata.
        assert!(!is_metadata_block(7, 1, spg, 16, 1024, 128, 1, &bgdt));
    }

    #[test]
    fn is_metadata_block_2kib_fs_forbids_block_0() {
        // 2 KiB fs: s_first_data_block = 0, primary SB lives inside
        // block 0. Block 0 must be forbidden explicitly (#617 item 1).
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
        // Block 0: primary SB on a 2 KiB fs — must be metadata.
        assert!(is_metadata_block(0, 0, 4096, 16, 2048, 128, 1, &bgdt));
        // BGDT at block 1 on a 2 KiB fs (group_start + 1 = 1).
        assert!(is_metadata_block(1, 0, 4096, 16, 2048, 128, 1, &bgdt));
    }

    #[test]
    fn is_metadata_block_forbids_backup_sb_and_bgdt() {
        // Two-group, 1 KiB filesystem matching the `balloc_test.img`
        // fixture (#617 item 1: backup SB at block 257, backup BGDT at
        // 258 must be in the forbidden map).
        let bgdt = alloc::vec![
            Ext2GroupDesc {
                bg_block_bitmap: 3,
                bg_inode_bitmap: 4,
                bg_inode_table: 5,
                bg_free_blocks_count: 0,
                bg_free_inodes_count: 0,
                bg_used_dirs_count: 0,
                bg_pad: 0,
                bg_reserved: [0; 12],
            },
            Ext2GroupDesc {
                bg_block_bitmap: 259,
                bg_inode_bitmap: 260,
                bg_inode_table: 261,
                bg_free_blocks_count: 0,
                bg_free_inodes_count: 0,
                bg_used_dirs_count: 0,
                bg_pad: 0,
                bg_reserved: [0; 12],
            },
        ];
        // Group 1 starts at s_first_data_block + 1 * s_blocks_per_group
        // = 1 + 256 = 257. SB backup at 257, BGDT backup at 258.
        assert!(is_metadata_block(257, 1, 256, 128, 1024, 128, 2, &bgdt));
        assert!(is_metadata_block(258, 1, 256, 128, 1024, 128, 2, &bgdt));
        // Block 268 is still inside group 1's inode table
        // (bg_inode_table=261; 128 inodes * 128 B = 16 KiB = 16 blocks
        // → 261..=276 actually; first non-metadata block in group 1 is
        // 277). Verify a clear non-metadata position:
        assert!(!is_metadata_block(300, 1, 256, 128, 1024, 128, 2, &bgdt));
        // Verify backup BGDT block is caught.
        assert!(is_metadata_block(258, 1, 256, 128, 1024, 128, 2, &bgdt));
    }
}
