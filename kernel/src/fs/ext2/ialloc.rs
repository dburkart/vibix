//! ext2 inode-bitmap allocator (#566).
//!
//! RFC 0004 §Block and inode allocation is the normative spec. This
//! module implements the **inode** allocator; the parallel block
//! allocator ([`super::balloc`]) is a sibling module with the same
//! read-modify-write (RMW) discipline and locking order.
//!
//! # Public surface
//!
//! - [`alloc_inode`] — allocate a free inode number, biased toward the
//!   parent directory's group for locality. Returns `ENOSPC` when no
//!   group has a free inode.
//! - [`free_inode`] — clear the bit for `ino` in its group's inode
//!   bitmap, bump `bg_free_inodes_count`, and decrement
//!   `bg_used_dirs_count` when `was_dir`.
//!
//! # Discipline (§Create write-ordering)
//!
//! Every on-disk mutation is read-modify-write through the buffer
//! cache: `bread` → mutate the slot in-place → `mark_dirty` →
//! `sync_dirty_buffer`. The sync is synchronous — the allocator must
//! return only after the bitmap bit has hit the device, because the
//! caller's next step (writing the inode slot with `i_mode != 0`) is
//! ordered after the bitmap set in the soft-update sequence.
//!
//! Order per call: bitmap bit first, then BGDT counter, then
//! superblock counter. Matches the block allocator in
//! [`super::balloc`].
//!
//! # Locking
//!
//! The entry points hold `super_.bgdt.lock()` across the bitmap RMW
//! and the BGDT counter update, then — still inside that guard —
//! take `super_.sb_disk.lock()` for the superblock update.
//! [`super::fs::Ext2Super`] documents the ordering: always `bgdt`
//! before `sb_disk`. `super_.alloc_mutex` is held at the outermost
//! level so two concurrent allocators can't interleave bitmap scans
//! with disjoint bgdt groups (a cross-group free-count drift).
//!
//! # Reserved-range guard
//!
//! Inode numbers `1..first_ino` are reserved for the driver (root
//! inode, bad-block inode, acl placeholders, journaling, …). This
//! allocator never returns a reserved ino, and [`free_inode`] refuses
//! one with `EINVAL` (a caller tried to free a reserved slot — almost
//! certainly a driver bug). `first_ino` is
//! [`super::disk::EXT2_GOOD_OLD_FIRST_INO`] (= 11) on rev-0 images or
//! `s_first_ino` on rev-1.
//!
//! # `s_inodes_count` bound
//!
//! Bits past `s_inodes_count` in the last group's bitmap are treated
//! as set: a well-formed `mkfs.ext2` image stamps them as 1 in the
//! inode bitmap's tail; we cap the scan at the last valid bit
//! regardless, to be defensive against a malformed image.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::disk::{Ext2GroupDesc, Ext2SuperBlock, EXT2_GROUP_DESC_SIZE, EXT2_SUPERBLOCK_SIZE};
use super::fs::{Ext2MountFlags, Ext2Super, SUPERBLOCK_BYTE_OFFSET};

use crate::fs::{EINVAL, EIO, ENOSPC, EROFS};

/// Allocate a free inode number and return it, with its bitmap bit set
/// and all counter deltas flushed to disk.
///
/// `parent_group_hint` is the block group of the parent directory —
/// the allocator tries that group first (RFC 0004 §Allocator: "try the
/// parent's group first"). On a miss, the fallback policy per #566 is
/// "pick the group with the most free inodes" — a mild Orlov-style
/// spread that keeps cold inodes from piling into one group.
///
/// `is_dir == true` bumps the target group's `bg_used_dirs_count`
/// (ext2's per-group directory tally, consulted by `e2fsck -D` and
/// the future Orlov full-allocator).
///
/// # Errors
///
/// - [`EROFS`]: the mount is read-only. No state is touched.
/// - [`ENOSPC`]: every group's `bg_free_inodes_count` is zero.
/// - [`EIO`]: bitmap or BGDT I/O failure; the on-disk state is left
///   consistent because each mutation syncs before the next begins.
pub fn alloc_inode(
    super_: &Arc<Ext2Super>,
    parent_group_hint: Option<u32>,
    is_dir: bool,
) -> Result<u32, i64> {
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    // Outer serialization: keeps two concurrent alloc_inode calls
    // from racing on cross-group counter drift when the parent-group
    // scan misses and we read other groups' free-counts.
    let _alloc_guard = super_.alloc_mutex.lock();

    // Snapshot the geometry we need before taking the bgdt lock.
    let (s_inodes_per_group, s_inodes_count, first_ino, s_first_data_block) = {
        let sb = super_.sb_disk.lock();
        (
            sb.s_inodes_per_group,
            sb.s_inodes_count,
            super_.first_ino,
            sb.s_first_data_block,
        )
    };
    if s_inodes_per_group == 0 {
        return Err(EIO);
    }
    let block_size = super_.block_size;

    let mut bgdt = super_.bgdt.lock();
    let n_groups = bgdt.len() as u32;
    if n_groups == 0 {
        return Err(EIO);
    }

    let hint = parent_group_hint.filter(|g| *g < n_groups);
    let order = build_group_order(&bgdt, hint, n_groups);

    for bg_idx in order {
        // Fast fail: if the BGDT free-count says zero, skip the
        // bitmap read. The bitmap itself is still the source of
        // truth for correctness — a lying counter just costs a
        // wasted scan, never a bad allocation.
        if bgdt[bg_idx as usize].bg_free_inodes_count == 0 {
            continue;
        }
        let bitmap_blk = bgdt[bg_idx as usize].bg_inode_bitmap as u64;

        // Group 0 carries the reserved-range guard: bits
        // `0..first_ino-1` map to reserved inos (bit 0 = ino 1,
        // bit 1 = ino 2 = EXT2_ROOT_INO, …, bit first_ino-2 =
        // ino first_ino-1). Skip those. Other groups: every bit
        // is user-allocatable.
        let reserved_bits = if bg_idx == 0 { first_ino - 1 } else { 0 };

        // `s_inodes_count` bounds the last valid bit in the last
        // group; all earlier groups are full s_inodes_per_group.
        let group_first_ino_no = bg_idx * s_inodes_per_group + 1;
        if group_first_ino_no > s_inodes_count {
            continue;
        }
        let group_last_ino_no = group_first_ino_no
            .saturating_add(s_inodes_per_group)
            .saturating_sub(1)
            .min(s_inodes_count);
        let max_bit_exclusive = group_last_ino_no - group_first_ino_no + 1;
        if reserved_bits >= max_bit_exclusive {
            continue;
        }

        // Read the bitmap block and look for the first zero in
        // `reserved_bits..max_bit_exclusive`. Set it while we hold
        // the buffer write lock.
        let bh = super_
            .cache
            .bread(super_.device_id, bitmap_blk)
            .map_err(|_| EIO)?;
        let found_bit = {
            let mut data = bh.data.write();
            find_and_set_first_zero_bit(&mut data, reserved_bits, max_bit_exclusive)
        };
        let Some(bit) = found_bit else {
            // The counter said free, the bitmap said full. Don't
            // retry this group (it would loop forever); try the
            // next in the order list.
            continue;
        };

        super_.cache.mark_dirty(&bh);
        super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;

        // Update the in-memory BGDT entry and flush it.
        {
            let bg = &mut bgdt[bg_idx as usize];
            bg.bg_free_inodes_count = bg.bg_free_inodes_count.saturating_sub(1);
            if is_dir {
                bg.bg_used_dirs_count = bg.bg_used_dirs_count.saturating_add(1);
            }
        }
        flush_bgdt_entry(
            super_,
            bg_idx,
            &bgdt[bg_idx as usize],
            s_first_data_block,
            block_size,
        )?;

        // Update the in-memory superblock counter and flush it.
        {
            let mut sb = super_.sb_disk.lock();
            sb.s_free_inodes_count = sb.s_free_inodes_count.saturating_sub(1);
            flush_superblock(super_, &sb)?;
        }

        return Ok(group_first_ino_no + bit);
    }

    Err(ENOSPC)
}

/// Free an inode number.
///
/// Clears bit `(ino - 1) % s_inodes_per_group` in group `(ino - 1) /
/// s_inodes_per_group`'s inode bitmap, bumps `bg_free_inodes_count`,
/// bumps `s_free_inodes_count`, and decrements `bg_used_dirs_count`
/// when `was_dir`.
///
/// # Errors
///
/// - [`EROFS`]: the mount is read-only.
/// - [`EINVAL`]: `ino == 0`, `ino < first_ino` (reserved range), or
///   `ino > s_inodes_count`.
/// - [`EIO`]: bitmap bit was already clear (double-free), BGDT or
///   superblock I/O failure.
pub fn free_inode(super_: &Arc<Ext2Super>, ino: u32, was_dir: bool) -> Result<(), i64> {
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    let _alloc_guard = super_.alloc_mutex.lock();

    let (s_inodes_per_group, s_inodes_count, first_ino, s_first_data_block) = {
        let sb = super_.sb_disk.lock();
        (
            sb.s_inodes_per_group,
            sb.s_inodes_count,
            super_.first_ino,
            sb.s_first_data_block,
        )
    };
    if ino == 0 || ino < first_ino || ino > s_inodes_count {
        return Err(EINVAL);
    }
    if s_inodes_per_group == 0 {
        return Err(EIO);
    }
    let block_size = super_.block_size;

    let mut bgdt = super_.bgdt.lock();
    let bg_idx = ((ino - 1) / s_inodes_per_group) as usize;
    let bit_in_group = (ino - 1) % s_inodes_per_group;
    if bg_idx >= bgdt.len() {
        return Err(EIO);
    }
    let bitmap_blk = bgdt[bg_idx].bg_inode_bitmap as u64;

    // Clear the bitmap bit.
    let bh = super_
        .cache
        .bread(super_.device_id, bitmap_blk)
        .map_err(|_| EIO)?;
    let was_set = {
        let mut data = bh.data.write();
        let byte = (bit_in_group / 8) as usize;
        let mask = 1u8 << (bit_in_group % 8);
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
        return Err(EIO);
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;

    {
        let bg = &mut bgdt[bg_idx];
        bg.bg_free_inodes_count = bg.bg_free_inodes_count.saturating_add(1);
        if was_dir {
            bg.bg_used_dirs_count = bg.bg_used_dirs_count.saturating_sub(1);
        }
    }
    flush_bgdt_entry(
        super_,
        bg_idx as u32,
        &bgdt[bg_idx],
        s_first_data_block,
        block_size,
    )?;

    {
        let mut sb = super_.sb_disk.lock();
        sb.s_free_inodes_count = sb.s_free_inodes_count.saturating_add(1);
        flush_superblock(super_, &sb)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

/// Build the group-walk order: parent group first, then the remaining
/// groups sorted by in-memory `bg_free_inodes_count` (greatest first —
/// locality + spread-then-fill). Takes the BGDT as a live slice under
/// the caller's lock; no blocking, no I/O.
fn build_group_order(bgdt: &[Ext2GroupDesc], hint: Option<u32>, n_groups: u32) -> Vec<u32> {
    let mut order: Vec<u32> = Vec::with_capacity(n_groups as usize);
    if let Some(h) = hint {
        order.push(h);
    }
    let mut rest: Vec<(u32, u16)> = Vec::with_capacity(n_groups as usize);
    for g in 0..n_groups {
        if Some(g) == hint {
            continue;
        }
        rest.push((g, bgdt[g as usize].bg_free_inodes_count));
    }
    // Stable sort by free-count descending. Ties resolve to original
    // group order, which is fine — lower-numbered groups win, matching
    // the RFC's linear-spill ordering.
    rest.sort_by(|a, b| b.1.cmp(&a.1));
    order.extend(rest.into_iter().map(|(g, _)| g));
    order
}

/// Scan `bitmap[reserved_bits..max_bit_exclusive]` for the first zero
/// bit, set it, and return the bit index. Returns `None` if every bit
/// in the range is already set.
///
/// Bits are numbered ext2-style: bit `b` lives at byte `b/8`, mask
/// `1 << (b % 8)`. The byte-at-a-time fast path short-circuits on
/// `0xFF` (all bits set) which is the common case in the allocated
/// prefix of a used group's bitmap.
fn find_and_set_first_zero_bit(
    bitmap: &mut [u8],
    reserved_bits: u32,
    max_bit_exclusive: u32,
) -> Option<u32> {
    if reserved_bits >= max_bit_exclusive {
        return None;
    }
    let first_byte = (reserved_bits / 8) as usize;
    let last_byte_inclusive = ((max_bit_exclusive - 1) / 8) as usize;
    if last_byte_inclusive >= bitmap.len() {
        return None;
    }
    for byte_idx in first_byte..=last_byte_inclusive {
        let b = bitmap[byte_idx];
        if b == 0xFF {
            continue;
        }
        for bit in 0..8u32 {
            let bit_pos = (byte_idx as u32) * 8 + bit;
            if bit_pos < reserved_bits {
                continue;
            }
            if bit_pos >= max_bit_exclusive {
                return None;
            }
            let mask = 1u8 << bit;
            if (b & mask) == 0 {
                bitmap[byte_idx] |= mask;
                return Some(bit_pos);
            }
        }
    }
    None
}

/// RMW-flush BGDT slot `group` back to disk. Matches the shape of
/// `super::balloc::flush_bgdt_entry` exactly — kept as a second copy
/// here rather than exported so each allocator module owns its own
/// disk-flush boundary.
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

/// RMW-flush the primary superblock back to its on-disk location.
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

#[cfg(test)]
mod tests {
    //! Host-side unit tests for pure arithmetic. The disk-backed
    //! round-trip lives in `kernel/tests/ext2_ialloc.rs`.
    use super::*;

    #[test]
    fn find_zero_bit_skips_reserved_prefix() {
        // Byte 0 all set (bits 0..=7 taken by reserved inos 1..=8).
        // Byte 1: bits 8, 9, 10 set (inos 9, 10, 11 reserved/used);
        // bit 11 (→ ino 12) is the first free.
        let mut bm = [0xFFu8, 0x07u8, 0x00, 0x00];
        // Reserved = 10 bits means we'd happily return bit 10 if it were
        // free — but in this fixture bit 10 is set. The first free at-or-
        // after bit 10 is bit 11.
        let found = find_and_set_first_zero_bit(&mut bm, 10, 32);
        assert_eq!(found, Some(11));
        // After the scan the bit is marked set.
        assert_eq!(bm[1], 0x0f);
    }

    #[test]
    fn find_zero_bit_respects_max_bit_exclusive() {
        // Every bit free, but cap scan at bit 5.
        let mut bm = [0u8; 4];
        assert_eq!(find_and_set_first_zero_bit(&mut bm, 0, 5), Some(0));
        assert_eq!(bm[0], 0x01);
        // Now the first free is bit 1; cap at 1 → None.
        let mut bm2 = [0x01u8; 4];
        assert_eq!(find_and_set_first_zero_bit(&mut bm2, 0, 1), None);
    }

    #[test]
    fn find_zero_bit_returns_none_when_full() {
        let mut bm = [0xFFu8; 2];
        assert_eq!(find_and_set_first_zero_bit(&mut bm, 0, 16), None);
    }

    #[test]
    fn find_zero_bit_returns_none_when_reserved_covers_range() {
        let mut bm = [0u8; 4];
        assert_eq!(find_and_set_first_zero_bit(&mut bm, 10, 10), None);
        // Reserved past the range → None.
        assert_eq!(find_and_set_first_zero_bit(&mut bm, 20, 10), None);
    }

    #[test]
    fn build_group_order_hint_first_then_most_free() {
        // Shapes matching a BGDT: construct four groups with free counts
        // [2, 5, 0, 7]. Hint = 2. Expected order: [2, 3 (7), 1 (5), 0 (2)].
        fn bg(free: u16) -> Ext2GroupDesc {
            Ext2GroupDesc {
                bg_block_bitmap: 0,
                bg_inode_bitmap: 0,
                bg_inode_table: 0,
                bg_free_blocks_count: 0,
                bg_free_inodes_count: free,
                bg_used_dirs_count: 0,
                bg_pad: 0,
                bg_reserved: [0u8; 12],
            }
        }
        let bgdt = [bg(2), bg(5), bg(0), bg(7)];
        let order = build_group_order(&bgdt, Some(2), 4);
        assert_eq!(order, alloc::vec![2, 3, 1, 0]);
    }

    #[test]
    fn build_group_order_no_hint_most_free_first() {
        // No hint → every group is sorted by free-count descending;
        // ties resolve to lower-numbered group first.
        fn bg(free: u16) -> Ext2GroupDesc {
            Ext2GroupDesc {
                bg_block_bitmap: 0,
                bg_inode_bitmap: 0,
                bg_inode_table: 0,
                bg_free_blocks_count: 0,
                bg_free_inodes_count: free,
                bg_used_dirs_count: 0,
                bg_pad: 0,
                bg_reserved: [0u8; 12],
            }
        }
        let bgdt = [bg(2), bg(5), bg(0), bg(7)];
        let order = build_group_order(&bgdt, None, 4);
        assert_eq!(
            order,
            alloc::vec![3, 1, 0, 2],
            "unhinted → purely free-count-desc, no group-0 bias"
        );
    }
}
