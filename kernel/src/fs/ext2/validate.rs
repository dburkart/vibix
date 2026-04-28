//! Mount-time block-group / bitmap consistency checks.
//!
//! RFC 0004 §Robustness / §Security require that the driver reject —
//! or at minimum demote to RO — images whose on-disk bookkeeping is
//! detectably inconsistent. `Ext2Fs::mount` already validates the
//! superblock magic, geometry, and feature-flag triple; this module
//! adds the cross-checks between the block-group descriptor table
//! (BGDT) and the bitmaps it indexes:
//!
//! 1. Per group: count clear bits in the block bitmap; the value must
//!    equal `bg_free_blocks_count`. Same for the inode bitmap and
//!    `bg_free_inodes_count`.
//! 2. Group 0's inode bitmap must mark the reserved-inode range
//!    (inos `1..first_ino`, including ino 2 = `EXT2_ROOT_INO`) as
//!    *allocated*.
//! 3. The superblock's `s_free_blocks_count` / `s_free_inodes_count`
//!    must equal the sum of the per-group counters.
//!
//! On any mismatch the validator logs (via `kwarn!`) the group and the
//! observed-vs-expected counts and returns [`ForceRo::Yes`]; the mount
//! path then sets `Ext2MountFlags::FORCED_RDONLY` so subsequent writes
//! are refused. Reads are still safe: a desync between the bitmap and
//! the counter only matters when we try to allocate or free.
//!
//! The validator runs as a raw walk *before* the `Arc<SuperBlock>` is
//! built, mirroring the orphan-chain validator (`super::orphan`). The
//! `ForceRo` verdict is collapsed into the same `effective_rdonly` path
//! that handles the unknown-RO_COMPAT and corrupt-orphan-chain cases.
//!
//! Out of scope (per #678): online repair, cross-checking inode
//! `i_blocks` totals against actual block-bitmap usage, validating the
//! BGDT block-bitmap / inode-bitmap / inode-table block numbers point
//! into sane locations (the allocator already refuses to hand out
//! metadata blocks via `is_metadata_block`).

use alloc::vec;

use crate::block::cache::{BlockCache, DeviceId};
use crate::kwarn;

use super::disk::{Ext2GroupDesc, Ext2SuperBlock, EXT2_GOOD_OLD_FIRST_INO, EXT2_GOOD_OLD_REV};
use super::orphan::ForceRo;

/// Mount-time BGDT / bitmap consistency check. See module docs.
///
/// `first_ino` is the resolved first user-allocatable inode number
/// (rev-0: 11; rev-1: `s_first_ino`). The mount path computes it once
/// during feature-flag gating and passes it in; we accept it as a
/// parameter rather than re-deriving from `sb_disk` so the validator
/// can't drift from the rest of the mount pipeline.
///
/// Returns:
/// - [`ForceRo::No`] when every cross-check passes.
/// - [`ForceRo::Yes`] on any mismatch. A `kwarn!` line per failed
///   check identifies the group + the observed-vs-expected values,
///   so a human can use `dumpe2fs` against the same image to confirm.
pub fn validate_bgdt(
    cache: &BlockCache,
    device_id: DeviceId,
    sb_disk: &Ext2SuperBlock,
    bgdt: &[Ext2GroupDesc],
    first_ino: u32,
) -> ForceRo {
    if bgdt.is_empty() {
        // The mount path already rejects a zero-group filesystem with
        // EINVAL before we run, so reaching this branch implies a
        // sequencing bug. Be loud and force RO rather than silently
        // pass.
        kwarn!("ext2: validate_bgdt: empty BGDT, forcing RO");
        return ForceRo::Yes;
    }

    let group_count = bgdt.len() as u32;
    let s_blocks_per_group = sb_disk.s_blocks_per_group;
    let s_inodes_per_group = sb_disk.s_inodes_per_group;
    let s_blocks_count = sb_disk.s_blocks_count;
    let s_inodes_count = sb_disk.s_inodes_count;
    let s_first_data_block = sb_disk.s_first_data_block;

    if s_blocks_per_group == 0 || s_inodes_per_group == 0 {
        // Geometry is checked by the mount path before we run; keep a
        // belt-and-braces guard so a future caller can't drive us into
        // a div-by-zero.
        kwarn!(
            "ext2: validate_bgdt: zero blocks_per_group ({}) or inodes_per_group ({}), forcing RO",
            s_blocks_per_group,
            s_inodes_per_group,
        );
        return ForceRo::Yes;
    }

    // Sums for the superblock-vs-BGDT cross-check at the end. The
    // per-group counter is u16 on disk; sum into u64 so a hostile
    // image with `0xffff` in every group can't overflow even at the
    // u32::MAX-group ceiling.
    let mut sum_free_blocks: u64 = 0;
    let mut sum_free_inodes: u64 = 0;

    for (idx, bg) in bgdt.iter().enumerate() {
        let group = idx as u32;

        let blocks_in_this_group = blocks_in_group(
            group,
            group_count,
            s_blocks_per_group,
            s_blocks_count,
            s_first_data_block,
        );
        let inodes_in_this_group =
            inodes_in_group(group, group_count, s_inodes_per_group, s_inodes_count);

        // ---- block bitmap ----
        let bb_clear = match read_and_count_clear_bits(
            cache,
            device_id,
            bg.bg_block_bitmap as u64,
            blocks_in_this_group,
        ) {
            Some(n) => n,
            None => {
                kwarn!(
                    "ext2: validate_bgdt: group {}: unreadable block bitmap at block {}, forcing RO",
                    group,
                    bg.bg_block_bitmap,
                );
                return ForceRo::Yes;
            }
        };
        if bb_clear != bg.bg_free_blocks_count as u32 {
            kwarn!(
                "ext2: validate_bgdt: group {}: block bitmap has {} clear bits, BGDT says bg_free_blocks_count={}; forcing RO",
                group,
                bb_clear,
                bg.bg_free_blocks_count,
            );
            return ForceRo::Yes;
        }

        // ---- inode bitmap ----
        let ib_clear = match read_and_count_clear_bits(
            cache,
            device_id,
            bg.bg_inode_bitmap as u64,
            inodes_in_this_group,
        ) {
            Some(n) => n,
            None => {
                kwarn!(
                    "ext2: validate_bgdt: group {}: unreadable inode bitmap at block {}, forcing RO",
                    group,
                    bg.bg_inode_bitmap,
                );
                return ForceRo::Yes;
            }
        };
        if ib_clear != bg.bg_free_inodes_count as u32 {
            kwarn!(
                "ext2: validate_bgdt: group {}: inode bitmap has {} clear bits, BGDT says bg_free_inodes_count={}; forcing RO",
                group,
                ib_clear,
                bg.bg_free_inodes_count,
            );
            return ForceRo::Yes;
        }

        // ---- reserved-inode-range check (group 0 only) ----
        // Inos `1..first_ino` are reserved (root=2 lives in there).
        // They map to bits `0..first_ino-1` of group 0's inode bitmap;
        // every one of those bits MUST be set.
        if group == 0 {
            if let Some(ino) =
                first_clear_reserved_ino(cache, device_id, bg.bg_inode_bitmap as u64, first_ino)
            {
                kwarn!(
                    "ext2: validate_bgdt: group 0: reserved inode {} is unallocated in inode bitmap, forcing RO",
                    ino,
                );
                return ForceRo::Yes;
            }
        }

        sum_free_blocks = sum_free_blocks.saturating_add(bg.bg_free_blocks_count as u64);
        sum_free_inodes = sum_free_inodes.saturating_add(bg.bg_free_inodes_count as u64);
    }

    // ---- superblock totals vs BGDT sums ----
    if sum_free_blocks != sb_disk.s_free_blocks_count as u64 {
        kwarn!(
            "ext2: validate_bgdt: sum of bg_free_blocks_count = {} but s_free_blocks_count = {}; forcing RO",
            sum_free_blocks,
            sb_disk.s_free_blocks_count,
        );
        return ForceRo::Yes;
    }
    if sum_free_inodes != sb_disk.s_free_inodes_count as u64 {
        kwarn!(
            "ext2: validate_bgdt: sum of bg_free_inodes_count = {} but s_free_inodes_count = {}; forcing RO",
            sum_free_inodes,
            sb_disk.s_free_inodes_count,
        );
        return ForceRo::Yes;
    }

    let _ = EXT2_GOOD_OLD_REV; // doc-import keep-alive
    let _ = EXT2_GOOD_OLD_FIRST_INO;

    ForceRo::No
}

/// Read `bitmap_block` through `cache` and count the number of clear
/// bits in `[0, bit_limit)`. Returns `None` on a `bread` error so the
/// caller can demote to RO with a meaningful error rather than burying
/// the EIO in a panic.
fn read_and_count_clear_bits(
    cache: &BlockCache,
    device_id: DeviceId,
    bitmap_block: u64,
    bit_limit: u32,
) -> Option<u32> {
    let bh = cache.bread(device_id, bitmap_block).ok()?;
    let data = bh.data.read();
    Some(count_clear_bits(&data, bit_limit))
}

/// Count clear bits in `[0, bit_limit)` of `bitmap` (LSB-first within
/// each byte — standard ext2 layout). Bits past `bit_limit` are
/// ignored, matching how the allocator caps its scan to
/// `blocks_in_group` / `inodes_in_group`: mkfs.ext2 sets the tail bits
/// to 1 to mark "past end of group," and we treat anything beyond
/// `bit_limit` as not-our-business.
///
/// Public-but-unexported (via `pub(crate)`) so the kernel-target
/// `#[cfg(test)]` module below and a future allocator-side reuse can
/// share the same implementation.
pub(crate) fn count_clear_bits(bitmap: &[u8], bit_limit: u32) -> u32 {
    let bit_limit = bit_limit as usize;
    if bit_limit == 0 {
        return 0;
    }
    let bytes_full = bit_limit / 8;
    let tail_bits = bit_limit % 8;

    // Cap by `bitmap.len()` so a corrupt-but-short bitmap block (e.g.
    // a buffer-cache short read on a malformed image) doesn't index
    // past the end. The truncation is itself a corruption signal but
    // the per-bit clear-count would still be defined.
    let mut count: u32 = 0;
    let full_iter_end = bytes_full.min(bitmap.len());
    for &b in &bitmap[..full_iter_end] {
        // count_zeros() on u8 returns the number of zero bits across
        // all 8 positions. u32 conversion is fine — max 8 per byte.
        count += b.count_zeros();
    }
    // Treat any bytes the bitmap is missing (because it's too short)
    // as fully "set" (worst-case for the caller — they'll see a
    // smaller free-bit count than the BGDT claims and force RO via
    // the count mismatch rather than via this helper). This matches
    // mkfs.ext2's tail-byte convention.
    //
    // The partial trailing byte only contributes its `tail_bits` low
    // positions; bits at and above `tail_bits` are off-bitmap and
    // don't count.
    if tail_bits > 0 && bytes_full < bitmap.len() {
        let b = bitmap[bytes_full];
        for off in 0..tail_bits {
            if b & (1u8 << off) == 0 {
                count += 1;
            }
        }
    }
    count
}

/// Return the first reserved-inode number (1-based, in
/// `1..first_ino`) whose bit in `inode_bitmap_block` is *clear* —
/// i.e. the bitmap claims it's free, which is a corruption.
///
/// Returns `None` if every reserved bit is set (the healthy case) or
/// if `first_ino <= 1` (no reserved range, which a mount-path geometry
/// check should already have rejected).
fn first_clear_reserved_ino(
    cache: &BlockCache,
    device_id: DeviceId,
    inode_bitmap_block: u64,
    first_ino: u32,
) -> Option<u32> {
    if first_ino <= 1 {
        return None;
    }
    let bh = cache.bread(device_id, inode_bitmap_block).ok()?;
    let data = bh.data.read();
    // Inos are 1-based; bit `i` in the bitmap corresponds to ino `i+1`.
    let bits_to_check = (first_ino - 1) as usize;
    for bit in 0..bits_to_check {
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if byte >= data.len() {
            // Bitmap shorter than the reserved range → corruption.
            return Some((bit as u32) + 1);
        }
        if data[byte] & mask == 0 {
            return Some((bit as u32) + 1);
        }
    }
    None
}

/// Number of blocks in the given group. Mirrors the allocator's
/// `blocks_in_group` (private to `balloc.rs`); duplicated here so the
/// validator can run before the allocator is in scope.
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
        let total_data_blocks = s_blocks_count.saturating_sub(s_first_data_block) as u64;
        let full_groups_blocks = (group_count - 1) as u64 * s_blocks_per_group as u64;
        total_data_blocks
            .saturating_sub(full_groups_blocks)
            .min(s_blocks_per_group as u64) as u32
    }
}

/// Number of inodes in the given group. Mirrors the allocator's
/// per-group inode count: every group except possibly the last is a
/// full `s_inodes_per_group`; the last group's count is the remainder
/// from `s_inodes_count`.
fn inodes_in_group(
    group: u32,
    group_count: u32,
    s_inodes_per_group: u32,
    s_inodes_count: u32,
) -> u32 {
    if group + 1 < group_count {
        s_inodes_per_group
    } else {
        let total = s_inodes_count as u64;
        let full = (group_count - 1) as u64 * s_inodes_per_group as u64;
        total.saturating_sub(full).min(s_inodes_per_group as u64) as u32
    }
}

// Keep `vec!` reachable for the host-test module below.
const _: fn() = || {
    let _ = vec![0u8; 0];
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_clear_bits_empty_limit() {
        assert_eq!(count_clear_bits(&[0xff, 0xff], 0), 0);
        assert_eq!(count_clear_bits(&[0x00, 0x00], 0), 0);
    }

    #[test]
    fn count_clear_bits_all_set_full_byte() {
        // Every bit set → zero clear bits.
        assert_eq!(count_clear_bits(&[0xff, 0xff], 16), 0);
        // First byte clear, second set → 8 clear bits.
        assert_eq!(count_clear_bits(&[0x00, 0xff], 16), 8);
        // First set, second clear → 8 clear bits.
        assert_eq!(count_clear_bits(&[0xff, 0x00], 16), 8);
    }

    #[test]
    fn count_clear_bits_respects_limit() {
        // Whole byte is clear, but limit only covers the low 3 bits.
        assert_eq!(count_clear_bits(&[0x00], 3), 3);
        // Limit straddles a byte boundary: low byte is 0xff, high byte
        // bit 0 is clear (rest don't matter past limit=9).
        assert_eq!(count_clear_bits(&[0xff, 0xfe], 9), 0);
        assert_eq!(count_clear_bits(&[0xff, 0xfe], 10), 1);
    }

    #[test]
    fn count_clear_bits_mixed_pattern() {
        // 0xa5 = 0b1010_0101 — 4 clear bits (positions 1, 3, 4, 6).
        assert_eq!(count_clear_bits(&[0xa5], 8), 4);
        // 0xa5 0x5a — total 8 clear bits.
        assert_eq!(count_clear_bits(&[0xa5, 0x5a], 16), 8);
    }

    #[test]
    fn count_clear_bits_short_bitmap_caps_at_end() {
        // Bitmap shorter than limit: bits past the bitmap aren't
        // considered clear. This matches the convention "missing tail
        // = padded with 1-bits."
        assert_eq!(count_clear_bits(&[0x00], 16), 8);
    }

    #[test]
    fn blocks_in_group_matches_allocator() {
        // 1024 total data blocks (s_first_data_block=0), 512 per group → 2 groups, both full.
        assert_eq!(blocks_in_group(0, 2, 512, 1024, 0), 512);
        assert_eq!(blocks_in_group(1, 2, 512, 1024, 0), 512);
        // 1 KiB ext2: 1024 blocks, 1 first_data_block → 2 groups: 512 + 511.
        assert_eq!(blocks_in_group(0, 2, 512, 1024, 1), 512);
        assert_eq!(blocks_in_group(1, 2, 512, 1024, 1), 511);
    }

    #[test]
    fn inodes_in_group_short_last_group() {
        // 100 inodes total, 64 per group → group 0 = 64, group 1 = 36.
        assert_eq!(inodes_in_group(0, 2, 64, 100), 64);
        assert_eq!(inodes_in_group(1, 2, 64, 100), 36);
        // Single group: clamps.
        assert_eq!(inodes_in_group(0, 1, 64, 50), 50);
    }
}
