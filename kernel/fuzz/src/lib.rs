//! Host-side fuzz harness for the vibix ext2 driver (issue #677).
//!
//! # What this fuzzes
//!
//! The driver is built up from a few pure-data + pure-logic layers that
//! don't need the kernel target to exercise:
//!
//! - [`disk`] — on-disk decoders (`Ext2SuperBlock`, `Ext2GroupDesc`,
//!   `Ext2Inode`, `Ext2DirEntry2`, `align4_rec_len`, ...). Re-included
//!   verbatim via `#[path]` from `kernel/src/fs/ext2/disk.rs`.
//! - [`dir`] — `DirEntryIter`, the per-block directory walker that
//!   validates `rec_len` / `name_len` / `file_type` / reserved-ino
//!   rules. Re-included verbatim from `kernel/src/fs/ext2/dir.rs`. The
//!   `block_backed` submodule inside `dir.rs` is gated on
//!   `feature = "ext2"` + `target_os = "none"` and so does not compile
//!   here — the fuzz harness intentionally exercises only the pure
//!   per-block iterator.
//!
//! # The fuzz driver
//!
//! [`fuzz_one`] walks an attacker-controlled byte slice as a virtual
//! block device and replays the **mount + read-root** path:
//!
//! 1. Decode the 1024-byte superblock at offset 1024. Validate `s_magic
//!    == 0xEF53`, `block_size().is_some()`, group count ≥ 1,
//!    `s_blocks_count` not larger than the device, INCOMPAT/RO_COMPAT
//!    feature bits sane.
//! 2. Decode the BGDT starting at the block immediately after the
//!    superblock. For each descriptor, validate that
//!    `bg_block_bitmap`, `bg_inode_bitmap`, `bg_inode_table` are inside
//!    the device and not nonsensically zero.
//! 3. Locate the root inode (ino 2) within the inode table of group 0.
//!    Decode it. Walk its `i_block[0..12]` direct slots and the single-
//!    indirect block at `i_block[12]` (treated as a `block_size / 4`
//!    array of `u32` pointers). For each pointer, validate it lies
//!    inside the data range and is not pointing back at the indirect
//!    block itself (the "self-loop" corruption from #677).
//! 4. For each direct directory data block, run [`dir::DirEntryIter`]
//!    over it and consume every yielded record (with bounded loop
//!    counts). Each `DirError::Corrupt` is an EIO — never a panic.
//! 5. For each entry that names a regular file (best-effort: we don't
//!    re-parse the inode to confirm), pretend to read it: walk a
//!    bounded number of direct + single-indirect block pointers from
//!    that file's inode and copy a small chunk out of each.
//!
//! Every error path returns `Err(FuzzExit::*)`. The driver never
//! panics, and bounds every loop with a hard iteration cap so a
//! degenerate image cannot wedge the harness.
//!
//! See `kernel/fuzz/README.md` for how to run cargo-fuzz against this
//! harness, and `xtask fuzz ext2` for the CI-friendly bounded-iteration
//! runner that walks the corpus + a deterministic mutation budget.

#![forbid(unsafe_code)]
#![allow(
    clippy::needless_range_loop,
    clippy::explicit_counter_loop,
    // `dir.rs` is re-included verbatim from the kernel crate; clippy
    // lints there are addressed in the kernel's lint job, not here.
    clippy::manual_is_multiple_of
)]

extern crate alloc;

#[path = "../../src/fs/ext2/disk.rs"]
pub mod disk;

#[path = "../../src/fs/ext2/dir.rs"]
pub mod dir;

use disk::{
    align4_rec_len, Ext2GroupDesc, Ext2Inode, Ext2SuperBlock, EXT2_GROUP_DESC_SIZE,
    EXT2_INODE_SIZE_V0, EXT2_MAGIC, EXT2_N_BLOCKS, EXT2_ROOT_INO, EXT2_SUPERBLOCK_SIZE,
    INCOMPAT_FILETYPE,
};

/// Surface shape of a single fuzz iteration. Returned by
/// [`fuzz_one`]. Every variant is a clean reject — none cause the
/// driver to panic, OOB, or hang.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzExit {
    /// Image was successfully walked end-to-end. No corruption found
    /// (not the same as "this is a valid filesystem" — only that no
    /// validator fired).
    Ok,
    /// Backing buffer is too small to even hold the superblock slot.
    TooShort,
    /// Bad superblock magic, bad `s_log_block_size`, or some other
    /// structural reject from the SB layer.
    BadSuperblock,
    /// BGDT didn't fit in the device, or an entry pointed outside the
    /// device.
    BadGroupDesc,
    /// Root inode slot was unreachable, or its `i_block[]` pointers
    /// went out of range / formed a self-loop.
    BadRootInode,
    /// A directory data block contained a malformed record.
    BadDirEntry,
    /// A file's `i_block[]` pointers were out of range or self-looped.
    BadFileBlocks,
    /// A bounded-iteration cap fired. Treated as a clean reject (the
    /// production driver would also bail at the same kind of bound).
    LoopCap,
}

/// Hard cap on directory records consumed per directory block. The
/// production iterator already validates `rec_len >= 8 + name_len` and
/// `cursor + rec_len <= block_end`, so this cap is purely defensive
/// against a logic bug in this harness's own loop.
const MAX_DIR_RECORDS_PER_BLOCK: usize = 4096;
/// Hard cap on the number of file inodes the harness will pretend to
/// read out of a single image. Keeps a directory full of regular-file
/// entries from blowing up the iteration budget.
const MAX_FILES_TO_READ: usize = 64;
/// Hard cap on the number of indirect-block pointers we'll follow per
/// inode. The on-disk layout caps a single-indirect block at
/// `block_size / 4` pointers; this is a safety net.
const MAX_INDIRECT_PTRS: usize = 16384;

/// One full fuzz iteration. `data` is the entire byte slice presented
/// as a virtual block device; the harness reads from it as if it were
/// a `BlockDevice`. Never panics for any input.
pub fn fuzz_one(data: &[u8]) -> FuzzExit {
    // 1. Superblock — must be readable at byte offset 1024.
    if data.len() < 1024 + EXT2_SUPERBLOCK_SIZE {
        return FuzzExit::TooShort;
    }
    let sb_slot = &data[1024..1024 + EXT2_SUPERBLOCK_SIZE];
    let sb = Ext2SuperBlock::decode(sb_slot);

    if sb.s_magic != EXT2_MAGIC {
        return FuzzExit::BadSuperblock;
    }
    let block_size = match sb.block_size() {
        Some(b) if (1024..=65_536).contains(&b) => b,
        _ => return FuzzExit::BadSuperblock,
    };
    // Group count ≥ 1 and `s_blocks_count` no larger than the device.
    if sb.s_blocks_count == 0 || sb.s_blocks_per_group == 0 || sb.s_inodes_per_group == 0 {
        return FuzzExit::BadSuperblock;
    }
    let device_blocks = (data.len() as u64) / (block_size as u64);
    if (sb.s_blocks_count as u64) > device_blocks {
        return FuzzExit::BadSuperblock;
    }
    let group_count = sb.s_blocks_count.div_ceil(sb.s_blocks_per_group).max(1);
    if group_count > 65_536 {
        // Sanity: a 16-bit BGDT index space is the implicit ceiling.
        return FuzzExit::BadSuperblock;
    }

    // Inode size: rev-0 hardcodes 128; rev-1 reads s_inode_size and
    // must satisfy 128 <= size <= block_size and be a power of two.
    let inode_size = if sb.s_rev_level == 0 {
        EXT2_INODE_SIZE_V0
    } else {
        let isz = sb.s_inode_size as usize;
        if !(EXT2_INODE_SIZE_V0..=block_size as usize).contains(&isz) || !isz.is_power_of_two() {
            return FuzzExit::BadSuperblock;
        }
        isz
    };

    // 2. BGDT — sits at block `s_first_data_block + 1`. Each slot is
    //    32 bytes regardless of `inode_size`.
    let bgdt_start_block = (sb.s_first_data_block as u64).saturating_add(1);
    let bgdt_byte_off = bgdt_start_block.saturating_mul(block_size as u64);
    let bgdt_byte_len = (group_count as u64).saturating_mul(EXT2_GROUP_DESC_SIZE as u64);
    let bgdt_byte_end = match bgdt_byte_off.checked_add(bgdt_byte_len) {
        Some(v) => v,
        None => return FuzzExit::BadGroupDesc,
    };
    if bgdt_byte_end > data.len() as u64 {
        return FuzzExit::BadGroupDesc;
    }
    let bgdt = &data[bgdt_byte_off as usize..bgdt_byte_end as usize];

    let mut group0: Option<Ext2GroupDesc> = None;
    for g in 0..group_count as usize {
        let off = g * EXT2_GROUP_DESC_SIZE;
        let gd = Ext2GroupDesc::decode(&bgdt[off..off + EXT2_GROUP_DESC_SIZE]);
        // Every per-group metadata block must lie inside the device.
        for b in [gd.bg_block_bitmap, gd.bg_inode_bitmap, gd.bg_inode_table] {
            if b == 0 || (b as u64) >= device_blocks {
                return FuzzExit::BadGroupDesc;
            }
        }
        // Free counts that exceed the per-group capacity are cheap to
        // catch and a known #677 corruption case.
        if gd.bg_free_inodes_count as u32 > sb.s_inodes_per_group {
            return FuzzExit::BadGroupDesc;
        }
        if gd.bg_free_blocks_count as u32 > sb.s_blocks_per_group {
            return FuzzExit::BadGroupDesc;
        }
        if g == 0 {
            group0 = Some(gd);
        }
    }
    let group0 = match group0 {
        Some(g) => g,
        None => return FuzzExit::BadGroupDesc,
    };

    // 3. Root inode (ino 2). Slot index within group 0 is
    //    `(EXT2_ROOT_INO - 1) * inode_size` bytes into the inode
    //    table.
    let inode_table_byte = (group0.bg_inode_table as u64).saturating_mul(block_size as u64);
    let root_slot_off = inode_table_byte
        .saturating_add(((EXT2_ROOT_INO - 1) as u64).saturating_mul(inode_size as u64));
    let root_slot_end = match root_slot_off.checked_add(EXT2_INODE_SIZE_V0 as u64) {
        Some(v) => v,
        None => return FuzzExit::BadRootInode,
    };
    if root_slot_end > data.len() as u64 {
        return FuzzExit::BadRootInode;
    }
    let root_inode = Ext2Inode::decode(&data[root_slot_off as usize..root_slot_end as usize]);

    // Walk the root directory's data blocks (12 direct + single
    // indirect) and run the per-block iterator. Collect the inos of
    // any regular files for the read-pretend pass below.
    let filetype_valid = (sb.s_feature_incompat & INCOMPAT_FILETYPE) != 0;
    // Track each candidate ino plus its dir-entry file_type so the
    // pretend-read pass below can decide whether a `BadFileBlocks` from
    // its inode is a real corruption (regular file → propagate) or a
    // benign shape mismatch (e.g. attacker named a directory, where
    // `i_block[]` semantics are different and a swallowed error is the
    // right call).
    let mut file_inos: alloc::vec::Vec<(u32, u8)> = alloc::vec::Vec::new();

    // Any error walking the *root* inode is structural corruption of
    // the root, not of "some file" — remap to `BadRootInode` so the
    // verdict matches the contract. `LoopCap` stays as itself: it's
    // the harness's own budget tripping, orthogonal to which inode
    // ran us out of pointers.
    let dir_blocks = match collect_data_blocks(data, &root_inode, block_size, device_blocks) {
        Ok(v) => v,
        Err(FuzzExit::LoopCap) => return FuzzExit::LoopCap,
        Err(_) => return FuzzExit::BadRootInode,
    };

    for blk in dir_blocks.iter().copied() {
        let block_bytes = match read_block(data, blk, block_size) {
            Some(b) => b,
            None => return FuzzExit::BadDirEntry,
        };
        let mut iter = dir::DirEntryIter::new(block_bytes, filetype_valid);
        let mut consumed = 0usize;
        loop {
            if consumed >= MAX_DIR_RECORDS_PER_BLOCK {
                return FuzzExit::LoopCap;
            }
            consumed += 1;
            match iter.next() {
                None => break,
                Some(Err(_)) => return FuzzExit::BadDirEntry,
                Some(Ok(view)) => {
                    // The iterator only emits records that already
                    // pass the structural validators (rec_len /
                    // name_len / inode != 0). Stash the ino for the
                    // pretend-read pass; we don't need to know whether
                    // it's a regular file — the secondary walk below
                    // tolerates non-files cleanly.
                    if file_inos.len() < MAX_FILES_TO_READ
                        && view.inode != EXT2_ROOT_INO
                        && (view.inode as u64) <= sb.s_inodes_count as u64
                    {
                        file_inos.push((view.inode, view.file_type));
                    }
                    // align4_rec_len is the same primitive the driver
                    // uses; running it on attacker bytes catches any
                    // arithmetic UB regression.
                    let _ = align4_rec_len(8 + view.name.len());
                }
            }
        }
    }

    // 5. Pretend-read each named ino. Resolve its inode slot like step
    //    3, walk a bounded number of its direct + single-indirect
    //    blocks, and bail cleanly on any out-of-range pointer or
    //    self-loop.
    for &(ino, file_type) in &file_inos {
        if ino < 1 {
            continue;
        }
        let group = ((ino - 1) / sb.s_inodes_per_group) as usize;
        let index_in_group = (ino - 1) % sb.s_inodes_per_group;
        if group >= group_count as usize {
            // Out-of-range ino — production code would EIO; we just
            // skip it and keep fuzzing the rest of the image.
            continue;
        }
        let bgdt_off = group * EXT2_GROUP_DESC_SIZE;
        let gd = Ext2GroupDesc::decode(&bgdt[bgdt_off..bgdt_off + EXT2_GROUP_DESC_SIZE]);
        let it_byte = (gd.bg_inode_table as u64).saturating_mul(block_size as u64);
        let slot_byte = it_byte.saturating_add((index_in_group as u64) * (inode_size as u64));
        let slot_end = match slot_byte.checked_add(EXT2_INODE_SIZE_V0 as u64) {
            Some(v) => v,
            None => continue,
        };
        if slot_end > data.len() as u64 {
            continue;
        }
        let inode = Ext2Inode::decode(&data[slot_byte as usize..slot_end as usize]);
        // Whether the dir entry positively names a regular file. If
        // `filetype_valid` is false (pre-rev-1 / no INCOMPAT_FILETYPE)
        // every entry surfaces as `EXT2_FT_UNKNOWN`, meaning we *cannot*
        // disambiguate — be conservative and treat it as "could be a
        // regular file" so we don't silently swallow real corruption.
        let entry_is_definitely_not_regular =
            filetype_valid && file_type != disk::EXT2_FT_REG_FILE;
        match collect_data_blocks(data, &inode, block_size, device_blocks) {
            Ok(blocks) => {
                for blk in blocks.iter().copied().take(MAX_INDIRECT_PTRS) {
                    if read_block(data, blk, block_size).is_none() {
                        return FuzzExit::BadFileBlocks;
                    }
                }
            }
            Err(FuzzExit::LoopCap) => return FuzzExit::LoopCap,
            Err(FuzzExit::BadFileBlocks) => {
                // Only swallow when we're sure this entry is not a
                // regular file. Otherwise propagate — corrupted file
                // block lists must surface as `BadFileBlocks`, that's
                // the variant's whole purpose.
                if entry_is_definitely_not_regular {
                    continue;
                }
                return FuzzExit::BadFileBlocks;
            }
            Err(_) => continue,
        }
    }

    FuzzExit::Ok
}

/// Read `block_size` bytes at logical block number `blk`. Returns
/// `None` if `blk == 0` (unallocated / sparse hole — not an error in
/// the read path) or if the block lies outside the byte-slice device.
fn read_block(data: &[u8], blk: u32, block_size: u32) -> Option<&[u8]> {
    if blk == 0 {
        return None;
    }
    let off = (blk as u64).checked_mul(block_size as u64)?;
    let end = off.checked_add(block_size as u64)?;
    if end > data.len() as u64 {
        return None;
    }
    Some(&data[off as usize..end as usize])
}

/// Walk an inode's `i_block[0..15]` and return the data-block numbers
/// it resolves to, validating that every pointer is inside the device
/// and not pointing back at an already-visited indirect block (the
/// classic #677 self-loop case).
fn collect_data_blocks(
    data: &[u8],
    inode: &Ext2Inode,
    block_size: u32,
    device_blocks: u64,
) -> Result<alloc::vec::Vec<u32>, FuzzExit> {
    use alloc::vec::Vec;

    let mut blocks: Vec<u32> = Vec::new();
    let ptrs_per_block = (block_size / 4) as usize;
    // Visited set for the current inode's indirect-block walk. Any
    // indirect block that points back at itself or at a previously-
    // visited indirect block is a self-loop → BadFileBlocks.
    let mut visited_indirect: Vec<u32> = Vec::new();

    // Direct blocks: i_block[0..12].
    for i in 0..12.min(EXT2_N_BLOCKS) {
        let b = inode.i_block[i];
        if b == 0 {
            continue;
        }
        if (b as u64) >= device_blocks {
            return Err(FuzzExit::BadFileBlocks);
        }
        blocks.push(b);
        if blocks.len() > MAX_INDIRECT_PTRS {
            return Err(FuzzExit::LoopCap);
        }
    }

    // Single indirect: i_block[12].
    if EXT2_N_BLOCKS > 12 {
        let ind = inode.i_block[12];
        if ind != 0 {
            if (ind as u64) >= device_blocks {
                return Err(FuzzExit::BadFileBlocks);
            }
            visited_indirect.push(ind);
            let ind_block = match read_block(data, ind, block_size) {
                Some(b) => b,
                None => return Err(FuzzExit::BadFileBlocks),
            };
            for i in 0..ptrs_per_block {
                let off = i * 4;
                let p = u32::from_le_bytes([
                    ind_block[off],
                    ind_block[off + 1],
                    ind_block[off + 2],
                    ind_block[off + 3],
                ]);
                if p == 0 {
                    continue;
                }
                if p == ind {
                    // Self-loop — explicitly listed in the issue body.
                    return Err(FuzzExit::BadFileBlocks);
                }
                if (p as u64) >= device_blocks {
                    return Err(FuzzExit::BadFileBlocks);
                }
                blocks.push(p);
                if blocks.len() > MAX_INDIRECT_PTRS {
                    return Err(FuzzExit::LoopCap);
                }
            }
        }
    }

    // Double indirect: i_block[13]. We walk one level (the L1 array of
    // L2 indirect blocks) but cap the L2 work hard so a maximally
    // adversarial image can't blow the budget. Self-loop check kicks in
    // against `visited_indirect`.
    if EXT2_N_BLOCKS > 13 {
        let dind = inode.i_block[13];
        if dind != 0 {
            if (dind as u64) >= device_blocks || visited_indirect.contains(&dind) {
                return Err(FuzzExit::BadFileBlocks);
            }
            visited_indirect.push(dind);
            let dind_block = match read_block(data, dind, block_size) {
                Some(b) => b,
                None => return Err(FuzzExit::BadFileBlocks),
            };
            // Global cap on pointer *words* inspected across the entire
            // double-indirect walk — both the L1 array and every L2
            // block. Without this an adversarial image where L1 is
            // entirely nonzero (so `walked` only counts L1 slots, all
            // legal) but every L2 block is sparse (so `blocks.len()`
            // never trips) can still force `ptrs_per_block^2` reads.
            // The cap mirrors the per-list limit since the surface area
            // is the same: we promise never to chew through more than
            // `MAX_INDIRECT_PTRS` pointer words on any single inode.
            let mut inspected_words = 0usize;
            for i in 0..ptrs_per_block {
                if inspected_words >= MAX_INDIRECT_PTRS {
                    return Err(FuzzExit::LoopCap);
                }
                inspected_words += 1;
                let off = i * 4;
                let l2 = u32::from_le_bytes([
                    dind_block[off],
                    dind_block[off + 1],
                    dind_block[off + 2],
                    dind_block[off + 3],
                ]);
                if l2 == 0 {
                    continue;
                }
                if (l2 as u64) >= device_blocks || visited_indirect.contains(&l2) {
                    return Err(FuzzExit::BadFileBlocks);
                }
                visited_indirect.push(l2);
                let l2_block = match read_block(data, l2, block_size) {
                    Some(b) => b,
                    None => return Err(FuzzExit::BadFileBlocks),
                };
                for j in 0..ptrs_per_block {
                    if inspected_words >= MAX_INDIRECT_PTRS {
                        return Err(FuzzExit::LoopCap);
                    }
                    inspected_words += 1;
                    let joff = j * 4;
                    let p = u32::from_le_bytes([
                        l2_block[joff],
                        l2_block[joff + 1],
                        l2_block[joff + 2],
                        l2_block[joff + 3],
                    ]);
                    if p == 0 {
                        continue;
                    }
                    if (p as u64) >= device_blocks {
                        return Err(FuzzExit::BadFileBlocks);
                    }
                    blocks.push(p);
                    if blocks.len() > MAX_INDIRECT_PTRS {
                        return Err(FuzzExit::LoopCap);
                    }
                }
            }
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden 64 KiB `mkfs.ext2` image must walk cleanly to
    /// completion. If this regresses, the harness is broken before any
    /// fuzz iteration runs.
    #[test]
    fn fuzz_one_accepts_golden_image() {
        let img: &[u8] = include_bytes!("../../src/fs/ext2/fixtures/golden.img");
        assert_eq!(fuzz_one(img), FuzzExit::Ok);
    }

    #[test]
    fn fuzz_one_rejects_short_buffer() {
        assert_eq!(fuzz_one(&[]), FuzzExit::TooShort);
        assert_eq!(fuzz_one(&[0u8; 1024]), FuzzExit::TooShort);
    }

    #[test]
    fn fuzz_one_rejects_zeroed_superblock() {
        let mut img = vec![0u8; 65_536];
        // Magic remains zero — must reject.
        assert_eq!(fuzz_one(&img), FuzzExit::BadSuperblock);
        // Even with magic patched in, the rest of the SB is still
        // zeros, so block_size = 1024 but s_blocks_count = 0.
        img[1024 + 56] = 0x53;
        img[1024 + 57] = 0xEF;
        assert_eq!(fuzz_one(&img), FuzzExit::BadSuperblock);
    }

    #[test]
    fn fuzz_one_rejects_bad_magic() {
        let mut img = include_bytes!("../../src/fs/ext2/fixtures/golden.img").to_vec();
        img[1024 + 56] = 0xAA;
        img[1024 + 57] = 0xBB;
        assert_eq!(fuzz_one(&img), FuzzExit::BadSuperblock);
    }

    #[test]
    fn fuzz_one_rejects_inflated_blocks_count() {
        let mut img = include_bytes!("../../src/fs/ext2/fixtures/golden.img").to_vec();
        // s_blocks_count is u32 at offset 4. Patch to a value far
        // larger than the 64-block device.
        img[1024 + 4..1024 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(fuzz_one(&img), FuzzExit::BadSuperblock);
    }

    #[test]
    fn fuzz_one_rejects_bad_log_block_size() {
        let mut img = include_bytes!("../../src/fs/ext2/fixtures/golden.img").to_vec();
        // s_log_block_size at offset 24, set to 32 → block_size() returns None.
        img[1024 + 24..1024 + 28].copy_from_slice(&32u32.to_le_bytes());
        assert_eq!(fuzz_one(&img), FuzzExit::BadSuperblock);
    }

    /// Fuzz never panics on completely random input. Cheap smoke
    /// against the most obvious arithmetic UB regressions.
    #[test]
    fn fuzz_one_does_not_panic_on_random_bytes() {
        let mut buf = vec![0u8; 4096];
        for seed in 0u64..32 {
            // Cheap PRNG: SplitMix64.
            let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for byte in buf.iter_mut() {
                s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = s;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                *byte = ((z ^ (z >> 31)) & 0xff) as u8;
            }
            let _ = fuzz_one(&buf);
        }
    }
}
