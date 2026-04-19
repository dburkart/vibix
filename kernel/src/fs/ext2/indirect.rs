//! ext2 indirect-block walker — logical block number → absolute LBA.
//!
//! RFC 0004 §Indirect-block walker (`docs/RFC/0004-ext2-filesystem-driver.md`)
//! is the normative spec. An ext2 inode addresses its data blocks through
//! `i_block[15]`: 12 direct slots, one single-indirect, one double-
//! indirect, and one triple-indirect slot. The mapping from a file-
//! relative logical block index to an absolute block number (LBA) walks
//! the correct chain, bounds-checking **every pointer** along the way —
//! the on-disk image is attacker-controlled, a crafted `i_block` or
//! indirect slot aimed at the BGDT / inode table / bitmap blocks is the
//! most dangerous confused-deputy attack in the whole driver.
//!
//! # Module shape
//!
//! The walker is deliberately factored away from [`super::disk::Ext2Inode`]
//! so that wave-2 inode refactors (#559) can evolve the inode struct
//! without breaking the read path landed here. The public entry point
//! ([`resolve_block`]) takes a structural `&[u32; EXT2_N_BLOCKS]` — the
//! raw `i_block[]` array — together with the geometry / metadata-forbidden
//! map and an optional per-inode cache. The caller (the inode read path)
//! is responsible for supplying those inputs off whatever in-memory inode
//! type it settles on.
//!
//! # Output semantics
//!
//! - `Ok(None)` — sparse hole. A zero pointer in any slot along the walk
//!   (direct, single-, double-, triple-indirect, or the final data
//!   pointer) surfaces here. The read path fills the caller's buffer
//!   with zeros for the block; the write path (Workstream E) allocates.
//! - `Ok(Some(abs))` — absolute block number, validated against
//!   `[s_first_data_block, s_blocks_count)` and the metadata-forbidden
//!   bitmap.
//! - `Err(WalkError::Io)` — the buffer cache could not read an indirect
//!   block. The caller maps this to `EIO`.
//! - `Err(WalkError::Corrupt)` — a pointer was out of range or aimed at a
//!   metadata region. The caller maps this to `EIO` **and** forces the
//!   mount read-only: continuing to mutate a filesystem whose pointers
//!   are lying is how confused-deputy privilege escalations happen.
//!
//! # Per-inode cache
//!
//! Resolving a logical block off a triple-indirect chain costs three
//! `bread`s. On a sequential read over a large file, the outer two are
//! the same block over and over; a small LRU keyed by
//! `logical_block → absolute_block` elides them. Capacity is intentionally
//! small ([`IndirectCache::CAPACITY`]) — four entries is enough to cover
//! the walker's worst-case single-pass read of the four indirection
//! levels, and the bounded size keeps `IndirectCache` embeddable inline
//! inside each in-memory inode without blowing the per-inode footprint.
//!
//! An `epoch: u64` stamp covers the invalidation hazard RFC 0004
//! §Indirect-block walker flags: if a concurrent writer bumps the
//! inode's epoch between a reader observing it and finishing the walk,
//! the reader re-walks rather than trusting its stale cached entry.
//! See the doc on [`IndirectCache`] for the full protocol.

#![allow(dead_code)]

use alloc::sync::Arc;

use super::disk::EXT2_N_BLOCKS;
use crate::block::cache::{BlockCache, DeviceId};

/// Number of direct pointers in `i_block[]` before the first indirect
/// slot (RFC 0004 §Indirect-block walker).
pub const EXT2_DIRECT_BLOCKS: usize = 12;

/// Index of the single-indirect slot within `i_block[]`.
pub const EXT2_IND_BLOCK: usize = EXT2_DIRECT_BLOCKS;

/// Index of the double-indirect slot within `i_block[]`.
pub const EXT2_DIND_BLOCK: usize = EXT2_DIRECT_BLOCKS + 1;

/// Index of the triple-indirect slot within `i_block[]`.
pub const EXT2_TIND_BLOCK: usize = EXT2_DIRECT_BLOCKS + 2;

/// Error out of [`resolve_block`]. Distinguished so the caller can
/// produce a bare `EIO` for I/O failures versus an `EIO`+force-RO for
/// structural corruption (see module docs).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// Buffer cache failed to read an indirect block. Maps to `EIO`;
    /// does *not* on its own force the mount RO — transient I/O is
    /// recoverable.
    Io,
    /// Pointer was outside `[s_first_data_block, s_blocks_count)` or
    /// aimed at a metadata-forbidden region. Maps to `EIO` **and**
    /// forces the mount RO per RFC 0004 §Security. Holes (`p == 0`) do
    /// **not** report as `Corrupt`; they surface as `Ok(None)`.
    Corrupt,
}

/// Static geometry snapshot needed by the walker. Populated from the
/// mount-time parsed superblock; cheap to copy so the walker takes it
/// by reference without exposing the whole `Ext2SuperBlock`.
///
/// Invariant: `ptrs_per_block == block_size / 4`. The ctor enforces it.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Geometry {
    /// Logical block size (bytes). Always a power of two and ≥ 1024 on
    /// any valid ext2 image.
    pub block_size: u32,
    /// Lowest legal data block. `s_first_data_block` on-disk. Any
    /// pointer strictly below this is corruption — the superblock and
    /// BGDT live at or below it.
    pub s_first_data_block: u32,
    /// One past the last legal data block. Any pointer ≥ this is
    /// corruption.
    pub s_blocks_count: u32,
    /// Number of `u32` entries in one indirect block —
    /// `block_size / 4`. Cached so the walker doesn't recompute it at
    /// every branch.
    pub ptrs_per_block: u32,
}

impl Geometry {
    /// Build a [`Geometry`] from the superblock fields the walker
    /// needs. Returns `None` if `block_size` is not a whole multiple of
    /// 4 (every ext2 block size is a power of two ≥ 1024, so this is a
    /// should-never-happen guard rather than a user-facing check).
    pub fn new(block_size: u32, s_first_data_block: u32, s_blocks_count: u32) -> Option<Self> {
        if block_size == 0 || block_size % 4 != 0 {
            return None;
        }
        Some(Self {
            block_size,
            s_first_data_block,
            s_blocks_count,
            ptrs_per_block: block_size / 4,
        })
    }

    /// `true` iff `p` is a legal data-block pointer (ignoring the
    /// metadata-forbidden bitmap): non-zero and within
    /// `[s_first_data_block, s_blocks_count)`.
    #[inline]
    pub fn in_data_range(&self, p: u32) -> bool {
        p != 0 && p >= self.s_first_data_block && p < self.s_blocks_count
    }
}

/// Sorted, non-overlapping list of absolute-block ranges the walker
/// must refuse to follow. Populated at mount time from the superblock
/// and BGDT:
///
/// - The superblock block itself (block 0 on ≥ 2 KiB filesystems;
///   block 1 on 1 KiB filesystems).
/// - The BGDT blocks.
/// - For every group `g`: `bg_block_bitmap[g]`, `bg_inode_bitmap[g]`,
///   and the contiguous inode-table run starting at
///   `bg_inode_table[g]`.
///
/// A pointer that lands in any of these ranges is an image-forged
/// confused-deputy attack (RFC 0004 §Indirect-block walker, the
/// "crafted image aims a user-data write at the BGDT" bullet).
///
/// Stored as a range list (rather than a bit per block) because the
/// forbidden regions are small — O(group_count) contiguous runs — and
/// the walker's cost model is dominated by the `bread`, not the bounds
/// check. Binary search is `O(log n)` and avoids the O(s_blocks_count)
/// bitmap allocation on very large filesystems.
///
/// # Range representation
///
/// `ranges[i] = (start, end_exclusive)`. Invariant (checked by
/// [`MetadataMap::from_sorted_ranges`]): ranges are sorted ascending
/// by `start`, non-overlapping, and `start < end_exclusive`.
#[derive(Debug, Clone, Default)]
pub struct MetadataMap {
    ranges: alloc::vec::Vec<(u32, u32)>,
}

impl MetadataMap {
    /// Build an empty map. Useful for unit tests that want to exercise
    /// bounds-only validation without a concrete BGDT.
    pub const fn empty() -> Self {
        Self {
            ranges: alloc::vec::Vec::new(),
        }
    }

    /// Build a [`MetadataMap`] from an already-sorted, non-overlapping
    /// iterator of `(start, end_exclusive)` ranges. Adjacent ranges are
    /// coalesced so the binary-search predicate stays tight; an empty
    /// range (`start == end_exclusive`) is dropped silently.
    ///
    /// # Panics
    ///
    /// Panics (debug only) if the input is not sorted ascending or
    /// overlaps. The mount path constructs the input in a deterministic
    /// order from the BGDT, so a violation here is a driver bug, not a
    /// hostile-image input — panicking is appropriate.
    pub fn from_sorted_ranges<I: IntoIterator<Item = (u32, u32)>>(iter: I) -> Self {
        let mut out: alloc::vec::Vec<(u32, u32)> = alloc::vec::Vec::new();
        let mut last_end: u32 = 0;
        let mut first = true;
        for (start, end) in iter {
            if start >= end {
                continue;
            }
            debug_assert!(
                first || start >= last_end,
                "MetadataMap::from_sorted_ranges: input not sorted / overlaps"
            );
            if let Some(back) = out.last_mut() {
                if back.1 == start {
                    // Coalesce touching ranges: [a,b) + [b,c) → [a,c).
                    back.1 = end;
                    last_end = end;
                    first = false;
                    continue;
                }
            }
            out.push((start, end));
            last_end = end;
            first = false;
        }
        Self { ranges: out }
    }

    /// `true` iff `blk` lies inside any forbidden range.
    pub fn contains(&self, blk: u32) -> bool {
        // Binary search for the last range whose `start <= blk`; then
        // check that range's `end_exclusive > blk`.
        match self.ranges.binary_search_by(|&(s, _)| s.cmp(&blk)) {
            Ok(_) => true, // start == blk exactly → in range
            Err(0) => false,
            Err(i) => {
                let (_s, e) = self.ranges[i - 1];
                blk < e
            }
        }
    }

    /// Accessor used by unit tests and by `sync_fs`-style diagnostics.
    pub fn as_ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }
}

/// Validate a single pointer read off disk. Returns
/// `Ok(None)` for a hole, `Ok(Some(p))` for a good pointer, and
/// `Err(WalkError::Corrupt)` for anything else.
///
/// Inlined because every walk step (four per triple-indirect
/// resolution, down to one for a direct block) calls through here —
/// the branch is short and the caller's hot loop benefits from the
/// fused check.
#[inline]
fn validate_pointer(p: u32, geom: &Geometry, md: &MetadataMap) -> Result<Option<u32>, WalkError> {
    if p == 0 {
        return Ok(None);
    }
    if p < geom.s_first_data_block || p >= geom.s_blocks_count {
        return Err(WalkError::Corrupt);
    }
    if md.contains(p) {
        return Err(WalkError::Corrupt);
    }
    Ok(Some(p))
}

/// Read a pointer at slot `index` out of the indirect block `abs`.
/// Wraps the two-step "`bread` + `read_u32_le` at offset `index * 4`",
/// including the bounds check that `index < ptrs_per_block` (a debug
/// invariant — the walker never computes an out-of-range index, but the
/// `assert` catches future refactors).
fn read_pointer_slot(
    cache: &BlockCache,
    dev: DeviceId,
    abs: u32,
    index: u32,
    geom: &Geometry,
) -> Result<u32, WalkError> {
    debug_assert!(
        index < geom.ptrs_per_block,
        "read_pointer_slot: index {} >= ptrs_per_block {}",
        index,
        geom.ptrs_per_block
    );
    let bh = cache.bread(dev, abs as u64).map_err(|_| WalkError::Io)?;
    let data = bh.data.read();
    let off = (index as usize) * 4;
    // `data.len() == cache.block_size() == geom.block_size`; the
    // `index < ptrs_per_block` assert above already bounded `off`.
    let slot: [u8; 4] = data[off..off + 4]
        .try_into()
        .expect("indirect pointer slot is exactly 4 bytes");
    Ok(u32::from_le_bytes(slot))
}

/// One entry in the per-inode indirect cache.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct CacheEntry {
    logical: u32,
    absolute: u32,
}

/// Small per-inode LRU keyed by `logical_block → absolute_block`.
///
/// Capacity is [`IndirectCache::CAPACITY`] (8). A linear scan over a
/// fixed-size array beats a `BTreeMap` at this size; the hot-path cost
/// is eight `u32` compares plus two moves on a hit.
///
/// # Invalidation
///
/// Concurrent writers that change the map (truncate / write-extend /
/// any `setattr` that remaps blocks) bump the inode's `epoch: u64`.
/// Readers:
///
/// 1. Record `start_epoch = cache.epoch()` *before* consulting the
///    cache.
/// 2. Consult the cache. On a hit, record the candidate.
/// 3. After finishing the walk (or returning the cache hit), re-read
///    `end_epoch = cache.epoch()`. If `end_epoch != start_epoch`,
///    throw away the answer and re-walk with the fresh epoch.
///
/// This is strictly stronger than lock-drop-on-write and avoids the
/// SMP stale-resolution hazard RFC 0004 §Indirect-block walker calls
/// out. The cache itself is single-threaded (guarded by the inode's
/// own `RwLock` in the read path), so internal ordering is
/// straightforward.
///
/// Only **non-hole** resolutions are cached. A sparse hole at logical
/// block `L` can become allocated on the very next `write()`; caching
/// `(L, 0)` would force us to disambiguate "hole" from "uncached" on
/// every hit. The read path already handles holes cheaply (no `bread`),
/// so missing the cache on a hole costs nothing.
#[derive(Debug, Default)]
pub struct IndirectCache {
    /// Fixed-capacity MRU-ordered entry list. `entries[0]` is the most
    /// recently used; pushes evict from the tail.
    entries: alloc::vec::Vec<CacheEntry>,
    /// Monotonic stamp. Bumped by [`IndirectCache::invalidate`];
    /// readers must observe the same value before and after the walk.
    epoch: u64,
}

impl IndirectCache {
    /// Maximum resident `(logical → absolute)` entries. Four would
    /// cover the walker's own working set (the triple + double +
    /// single indirect block indices plus one data block); eight
    /// leaves headroom for a reader that's walking two files
    /// simultaneously through the same inode cache (not a legal VFS
    /// state today, but the extra slots are cheap).
    pub const CAPACITY: usize = 8;

    /// Construct an empty cache, epoch 0.
    pub const fn new() -> Self {
        Self {
            entries: alloc::vec::Vec::new(),
            epoch: 0,
        }
    }

    /// Current invalidation epoch. Used by readers to detect a
    /// concurrent writer (see module docs on the per-inode cache
    /// protocol).
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Bump the invalidation epoch and drop every entry. Called by
    /// truncate / write-extend / any `setattr` that remaps the block
    /// chain. Saturating at `u64::MAX` — a filesystem that churns its
    /// block map 2^64 times has bigger problems.
    pub fn invalidate(&mut self) {
        self.entries.clear();
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Look up `logical` in the cache. Moves the hit to the front of
    /// the MRU list (`entries[0]`) so subsequent reads stay fast.
    pub fn lookup(&mut self, logical: u32) -> Option<u32> {
        let pos = self.entries.iter().position(|e| e.logical == logical)?;
        if pos != 0 {
            let entry = self.entries.remove(pos);
            self.entries.insert(0, entry);
        }
        Some(self.entries[0].absolute)
    }

    /// Insert `(logical → absolute)` at the front of the MRU list.
    /// Evicts the oldest entry if already at [`CAPACITY`]. If `logical`
    /// is already resident the existing slot is overwritten in place
    /// (and promoted to MRU) — this keeps the cache consistent if the
    /// caller's walk produced a different answer than the stale entry.
    pub fn insert(&mut self, logical: u32, absolute: u32) {
        if let Some(pos) = self.entries.iter().position(|e| e.logical == logical) {
            self.entries.remove(pos);
        } else if self.entries.len() >= Self::CAPACITY {
            self.entries.pop();
        }
        self.entries.insert(0, CacheEntry { logical, absolute });
    }

    /// Accessor for unit tests.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Convenience: `true` iff the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Resolve a file-relative logical block index to an absolute block
/// number.
///
/// The walker follows the same four-level chain the on-disk format
/// describes (12 direct / 1 single / 1 double / 1 triple). Every
/// pointer — including the final data-block pointer — is validated via
/// [`validate_pointer`]. Zero pointers at any level surface as
/// `Ok(None)` (sparse hole); out-of-range or metadata-aliasing pointers
/// surface as `Err(WalkError::Corrupt)`.
///
/// `cache_opt` is the per-inode [`IndirectCache`] (see module docs).
/// Pass `None` to disable caching — useful for tests, for cold-path
/// callers, and for writers that have already invalidated the inode's
/// cache at the start of their own critical section.
///
/// # Cost
///
/// - Direct (`logical < 12`): no `bread`, no cache lookup needed — a
///   direct slot read out of the in-memory `i_block[]` array. The cache
///   is still checked / updated for consistency with the indirect path,
///   but the saved work is tiny.
/// - Single indirect: 1 `bread` on miss; 0 on hit.
/// - Double indirect: 2 `bread`s on miss; 0 on hit.
/// - Triple indirect: 3 `bread`s on miss; 0 on hit.
pub fn resolve_block(
    cache: &Arc<BlockCache>,
    dev: DeviceId,
    geom: &Geometry,
    md: &MetadataMap,
    i_block: &[u32; EXT2_N_BLOCKS],
    logical: u32,
    mut cache_opt: Option<&mut IndirectCache>,
) -> Result<Option<u32>, WalkError> {
    // Cache lookup — with the epoch-stable read protocol. The lookup
    // itself mutates the MRU order, so we snapshot the hit *and*
    // re-check the epoch. See `IndirectCache` docs for the full
    // protocol.
    let start_epoch = cache_opt.as_deref().map(|c| c.epoch());
    if let Some(cached) = cache_opt.as_deref_mut().and_then(|c| c.lookup(logical)) {
        // Re-validate: epoch may have been bumped by a concurrent
        // writer between our pre-snapshot and the lookup. In the
        // single-threaded case this can't happen (we hold the inode's
        // lock exclusively around the whole walk); the check is cheap
        // insurance for the future SMP path that lets readers share.
        let end_epoch = cache_opt.as_deref().map(|c| c.epoch());
        if start_epoch == end_epoch {
            return Ok(Some(cached));
        }
        // Epoch moved — fall through to the full walk and re-insert.
    }

    let p = geom.ptrs_per_block;
    let direct_limit: u32 = EXT2_DIRECT_BLOCKS as u32;
    // Compute the boundaries without overflow. On a pathological 64 KiB
    // block size `p = 16384`, `p^2 = 2^28`, `p^3 = 2^42` — comfortably
    // inside `u64`. Using `u64` for the cutoffs keeps the arithmetic
    // overflow-safe independent of block size.
    let p64 = p as u64;
    let single_limit: u64 = direct_limit as u64 + p64;
    let double_limit: u64 = single_limit + p64 * p64;
    let triple_limit: u64 = double_limit + p64 * p64 * p64;

    let logical64 = logical as u64;
    let resolved: Option<u32> = if logical < direct_limit {
        // Direct: the slot is `i_block[logical]`.
        validate_pointer(i_block[logical as usize], geom, md)?
    } else if logical64 < single_limit {
        // Single indirect.
        let idx0 = (logical64 - direct_limit as u64) as u32;
        let ind = match validate_pointer(i_block[EXT2_IND_BLOCK], geom, md)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let data_ptr = read_pointer_slot(cache, dev, ind, idx0, geom)?;
        validate_pointer(data_ptr, geom, md)?
    } else if logical64 < double_limit {
        // Double indirect.
        let rel = logical64 - single_limit;
        let idx_outer = (rel / p64) as u32;
        let idx_inner = (rel % p64) as u32;
        let dind = match validate_pointer(i_block[EXT2_DIND_BLOCK], geom, md)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let ind_ptr = read_pointer_slot(cache, dev, dind, idx_outer, geom)?;
        let ind = match validate_pointer(ind_ptr, geom, md)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let data_ptr = read_pointer_slot(cache, dev, ind, idx_inner, geom)?;
        validate_pointer(data_ptr, geom, md)?
    } else if logical64 < triple_limit {
        // Triple indirect.
        let rel = logical64 - double_limit;
        let p_squared = p64 * p64;
        let idx_l0 = (rel / p_squared) as u32;
        let rem = rel % p_squared;
        let idx_l1 = (rem / p64) as u32;
        let idx_l2 = (rem % p64) as u32;
        let tind = match validate_pointer(i_block[EXT2_TIND_BLOCK], geom, md)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let dind_ptr = read_pointer_slot(cache, dev, tind, idx_l0, geom)?;
        let dind = match validate_pointer(dind_ptr, geom, md)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let ind_ptr = read_pointer_slot(cache, dev, dind, idx_l1, geom)?;
        let ind = match validate_pointer(ind_ptr, geom, md)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let data_ptr = read_pointer_slot(cache, dev, ind, idx_l2, geom)?;
        validate_pointer(data_ptr, geom, md)?
    } else {
        // Past triple-indirect — logical block beyond `MAX_FILESIZE`.
        // An ext2 file is structurally incapable of holding more
        // blocks; the caller's `i_size` bound should have rejected
        // this read already. Surface as a hole so the read path zero-
        // fills rather than forcing RO — an out-of-range *index* is
        // the caller's bug, not an attacker-forged pointer.
        return Ok(None);
    };

    // Cache update — only non-hole resolutions, per module docs.
    if let (Some(abs), Some(c)) = (resolved, cache_opt.as_deref_mut()) {
        c.insert(logical, abs);
    }

    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Host unit tests for the indirect walker.
    //!
    //! The tests build a toy filesystem in a [`RamDisk`]-backed
    //! [`BlockCache`]:
    //!
    //! - Block size 1024 → `ptrs_per_block = 256`.
    //! - `s_first_data_block = 1`, `s_blocks_count = 2048`.
    //! - `MetadataMap` marks block 1 (superblock) and block 2 (BGDT)
    //!   as forbidden; data blocks live in `[10, 2048)`.
    //!
    //! The in-memory `i_block[15]` is written by hand per test. Each
    //! test asserts the walker's behaviour on one of the four
    //! addressing paths plus the hole / bounds / metadata cases.
    use super::*;
    use crate::block::cache::BlockCache;
    use crate::block::{BlockDevice, BlockError};
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use spin::Mutex;

    const BS: u32 = 1024;
    const PPB: u32 = BS / 4; // 256

    /// Minimal `BlockDevice`: a byte-addressable ramdisk. Panics on
    /// misaligned I/O — the cache and walker should never produce
    /// misaligned requests.
    struct RamDisk {
        bytes: Mutex<Box<[u8]>>,
    }

    impl RamDisk {
        fn new(blocks: usize) -> Arc<Self> {
            Arc::new(Self {
                bytes: Mutex::new(vec![0u8; blocks * BS as usize].into_boxed_slice()),
            })
        }

        /// Write `buf` at absolute block `blk`.
        fn put(&self, blk: u64, buf: &[u8]) {
            let mut b = self.bytes.lock();
            let off = (blk * BS as u64) as usize;
            assert!(off + buf.len() <= b.len());
            b[off..off + buf.len()].copy_from_slice(buf);
        }

        /// Write `slots` as a little-endian `u32` array starting at
        /// absolute block `blk`.
        fn put_ptrs(&self, blk: u64, slots: &[u32]) {
            let mut raw = vec![0u8; BS as usize];
            for (i, &v) in slots.iter().enumerate() {
                let off = i * 4;
                raw[off..off + 4].copy_from_slice(&v.to_le_bytes());
            }
            self.put(blk, &raw);
        }
    }

    impl BlockDevice for RamDisk {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            if offset % BS as u64 != 0 || buf.len() as u64 % BS as u64 != 0 || buf.is_empty() {
                return Err(BlockError::BadAlign);
            }
            let b = self.bytes.lock();
            let off = offset as usize;
            if off + buf.len() > b.len() {
                return Err(BlockError::OutOfRange);
            }
            buf.copy_from_slice(&b[off..off + buf.len()]);
            Ok(())
        }
        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), BlockError> {
            if offset % BS as u64 != 0 || buf.len() as u64 % BS as u64 != 0 || buf.is_empty() {
                return Err(BlockError::BadAlign);
            }
            let mut b = self.bytes.lock();
            let off = offset as usize;
            if off + buf.len() > b.len() {
                return Err(BlockError::Enospc);
            }
            b[off..off + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn block_size(&self) -> u32 {
            BS
        }
        fn capacity(&self) -> u64 {
            self.bytes.lock().len() as u64
        }
    }

    /// Stand up a fresh (RamDisk, BlockCache, DeviceId) triple sized
    /// for 2048 blocks of 1 KiB each.
    fn mk_fs() -> (
        Arc<RamDisk>,
        Arc<BlockCache>,
        DeviceId,
        Geometry,
        MetadataMap,
    ) {
        let disk = RamDisk::new(2048);
        let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, BS, 64);
        let dev = cache.register_device();
        let geom = Geometry::new(BS, 1, 2048).expect("Geometry::new");
        // Mark blocks 1 (superblock) and 2 (BGDT) as metadata-forbidden.
        let md = MetadataMap::from_sorted_ranges([(1, 3)]);
        (disk, cache, dev, geom, md)
    }

    #[test]
    fn metadata_map_sorted_and_coalesced() {
        let md = MetadataMap::from_sorted_ranges([(1, 3), (3, 5), (10, 12)]);
        // (1,3) + (3,5) coalesce into (1,5). (10,12) stays separate.
        assert_eq!(md.as_ranges(), &[(1, 5), (10, 12)]);
        assert!(md.contains(1));
        assert!(md.contains(4));
        assert!(!md.contains(5));
        assert!(!md.contains(9));
        assert!(md.contains(10));
        assert!(md.contains(11));
        assert!(!md.contains(12));
    }

    #[test]
    fn direct_resolution_returns_absolute_block() {
        let (_disk, cache, dev, geom, md) = mk_fs();
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[0] = 100;
        ib[5] = 150;
        ib[11] = 200;
        let r = resolve_block(&cache, dev, &geom, &md, &ib, 0, None).unwrap();
        assert_eq!(r, Some(100));
        let r = resolve_block(&cache, dev, &geom, &md, &ib, 5, None).unwrap();
        assert_eq!(r, Some(150));
        let r = resolve_block(&cache, dev, &geom, &md, &ib, 11, None).unwrap();
        assert_eq!(r, Some(200));
    }

    #[test]
    fn direct_hole_returns_none() {
        let (_disk, cache, dev, geom, md) = mk_fs();
        let ib = [0u32; EXT2_N_BLOCKS];
        let r = resolve_block(&cache, dev, &geom, &md, &ib, 3, None).unwrap();
        assert_eq!(r, None);
    }

    #[test]
    fn out_of_range_pointer_is_corrupt() {
        let (_disk, cache, dev, geom, md) = mk_fs();
        let mut ib = [0u32; EXT2_N_BLOCKS];
        // s_blocks_count = 2048 → 2048 is one past the last legal block.
        ib[0] = 2048;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 0, None),
            Err(WalkError::Corrupt)
        );
        // Below s_first_data_block = 1 → 0 is a hole (legal), but a
        // pointer to block 0 via a nonzero direct slot can't happen —
        // 0 IS the hole sentinel. Try pointing at block `s_first_data_block - 1`
        // on a geometry whose first_data_block = 2:
        let geom2 = Geometry::new(BS, 2, 2048).unwrap();
        ib[0] = 1;
        assert_eq!(
            resolve_block(&cache, dev, &geom2, &md, &ib, 0, None),
            Err(WalkError::Corrupt)
        );
    }

    #[test]
    fn metadata_aliased_pointer_is_corrupt() {
        let (_disk, cache, dev, geom, md) = mk_fs();
        let mut ib = [0u32; EXT2_N_BLOCKS];
        // Block 1 is in the metadata-forbidden range (superblock).
        ib[0] = 1;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 0, None),
            Err(WalkError::Corrupt)
        );
    }

    #[test]
    fn single_indirect_resolution() {
        let (disk, cache, dev, geom, md) = mk_fs();
        // Put an indirect block at absolute block 100. Slot 0 → 500,
        // slot 7 → 507, slot 255 → 755.
        let mut slots = vec![0u32; PPB as usize];
        slots[0] = 500;
        slots[7] = 507;
        slots[255] = 755;
        disk.put_ptrs(100, &slots);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_IND_BLOCK] = 100;
        // Logical block 12 → indirect slot 0 → absolute 500.
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 12, None).unwrap(),
            Some(500)
        );
        // Logical block 19 → indirect slot 7 → absolute 507.
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 19, None).unwrap(),
            Some(507)
        );
        // Logical block 12 + 255 = 267 → indirect slot 255 → absolute 755.
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 267, None).unwrap(),
            Some(755)
        );
    }

    #[test]
    fn single_indirect_hole_at_slot() {
        let (disk, cache, dev, geom, md) = mk_fs();
        // Indirect block all-zero.
        disk.put_ptrs(100, &vec![0u32; PPB as usize]);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_IND_BLOCK] = 100;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 12, None).unwrap(),
            None
        );
    }

    #[test]
    fn single_indirect_unallocated_ind_ptr_is_hole() {
        let (_disk, cache, dev, geom, md) = mk_fs();
        // The single-indirect slot itself is zero → whole range is a
        // hole. No bread required.
        let ib = [0u32; EXT2_N_BLOCKS];
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 12, None).unwrap(),
            None
        );
    }

    #[test]
    fn single_indirect_corrupt_slot_is_eio() {
        let (disk, cache, dev, geom, md) = mk_fs();
        let mut slots = vec![0u32; PPB as usize];
        slots[0] = 99_999; // past s_blocks_count
        disk.put_ptrs(100, &slots);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_IND_BLOCK] = 100;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, 12, None),
            Err(WalkError::Corrupt)
        );
    }

    #[test]
    fn double_indirect_resolution() {
        let (disk, cache, dev, geom, md) = mk_fs();
        // Double-indirect lives at block 200. Its first slot points at
        // a single-indirect at block 201; that indirect's slot 3 points
        // at data block 300.
        let mut outer = vec![0u32; PPB as usize];
        outer[0] = 201;
        disk.put_ptrs(200, &outer);
        let mut inner = vec![0u32; PPB as usize];
        inner[3] = 300;
        disk.put_ptrs(201, &inner);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_DIND_BLOCK] = 200;
        // logical = 12 + 256 (single range) + 3 (inner slot) = 271.
        let logical = 12 + PPB + 3;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, logical, None).unwrap(),
            Some(300)
        );
    }

    #[test]
    fn double_indirect_outer_hole_is_hole() {
        let (disk, cache, dev, geom, md) = mk_fs();
        // Outer all-zero → the specific inner slot is a hole.
        disk.put_ptrs(200, &vec![0u32; PPB as usize]);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_DIND_BLOCK] = 200;
        let logical = 12 + PPB + 3;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, logical, None).unwrap(),
            None
        );
    }

    #[test]
    fn triple_indirect_resolution() {
        let (disk, cache, dev, geom, md) = mk_fs();
        // Triple-indirect at block 300. slot 0 → double-indirect at
        // block 301. That double-indirect slot 0 → single-indirect at
        // block 302. That single-indirect slot 5 → data block 400.
        let mut l0 = vec![0u32; PPB as usize];
        l0[0] = 301;
        disk.put_ptrs(300, &l0);
        let mut l1 = vec![0u32; PPB as usize];
        l1[0] = 302;
        disk.put_ptrs(301, &l1);
        let mut l2 = vec![0u32; PPB as usize];
        l2[5] = 400;
        disk.put_ptrs(302, &l2);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_TIND_BLOCK] = 300;
        let p = PPB as u32;
        // logical = 12 + p (single) + p^2 (double) + 0 * p^2 + 0 * p + 5
        //        = 12 + p + p^2 + 5.
        let logical = 12 + p + p * p + 5;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, logical, None).unwrap(),
            Some(400)
        );
    }

    #[test]
    fn triple_indirect_inner_hole_is_hole() {
        let (disk, cache, dev, geom, md) = mk_fs();
        let mut l0 = vec![0u32; PPB as usize];
        l0[0] = 301;
        disk.put_ptrs(300, &l0);
        // Double-indirect slot is zero → inner chain is a hole.
        disk.put_ptrs(301, &vec![0u32; PPB as usize]);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_TIND_BLOCK] = 300;
        let p = PPB as u32;
        let logical = 12 + p + p * p + 5;
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, logical, None).unwrap(),
            None
        );
    }

    #[test]
    fn past_triple_indirect_is_hole() {
        // Logical index past 12 + P + P^2 + P^3 is structurally
        // unreachable. Surface as hole so the caller's zero-fill path
        // handles it without forcing RO.
        let (_disk, cache, dev, geom, md) = mk_fs();
        let ib = [0u32; EXT2_N_BLOCKS];
        let max_logical = 12u64 + PPB as u64 + (PPB as u64).pow(2) + (PPB as u64).pow(3);
        assert_eq!(
            resolve_block(&cache, dev, &geom, &md, &ib, max_logical as u32, None).unwrap(),
            None
        );
    }

    #[test]
    fn cache_hit_avoids_second_bread() {
        // First call populates the cache; second call on the same
        // logical block must return the same answer. The test itself
        // can't easily instrument bread count, but we can at least
        // cover the hit path and the MRU promotion.
        let (disk, cache, dev, geom, md) = mk_fs();
        let mut slots = vec![0u32; PPB as usize];
        slots[0] = 500;
        disk.put_ptrs(100, &slots);
        let mut ib = [0u32; EXT2_N_BLOCKS];
        ib[EXT2_IND_BLOCK] = 100;
        let mut icache = IndirectCache::new();
        let r = resolve_block(&cache, dev, &geom, &md, &ib, 12, Some(&mut icache)).unwrap();
        assert_eq!(r, Some(500));
        assert_eq!(icache.len(), 1);
        assert_eq!(icache.lookup(12), Some(500));
        // Second call should still return the same result — whether
        // via cache or re-walk.
        let r = resolve_block(&cache, dev, &geom, &md, &ib, 12, Some(&mut icache)).unwrap();
        assert_eq!(r, Some(500));
        assert_eq!(icache.len(), 1);
    }

    #[test]
    fn cache_invalidate_bumps_epoch_and_clears() {
        let mut c = IndirectCache::new();
        c.insert(1, 100);
        c.insert(2, 200);
        assert_eq!(c.len(), 2);
        let e0 = c.epoch();
        c.invalidate();
        assert_eq!(c.epoch(), e0 + 1);
        assert!(c.is_empty());
        // Re-insert works.
        c.insert(3, 300);
        assert_eq!(c.lookup(3), Some(300));
    }

    #[test]
    fn cache_evicts_oldest_at_capacity() {
        let mut c = IndirectCache::new();
        for i in 0..IndirectCache::CAPACITY as u32 {
            c.insert(i, i * 10);
        }
        assert_eq!(c.len(), IndirectCache::CAPACITY);
        // Inserting one more should evict the least-recently-used
        // entry, which is logical=0.
        c.insert(99, 990);
        assert_eq!(c.len(), IndirectCache::CAPACITY);
        assert_eq!(c.lookup(0), None);
        assert_eq!(c.lookup(99), Some(990));
    }

    #[test]
    fn cache_does_not_store_holes() {
        let (_disk, cache, dev, geom, md) = mk_fs();
        let ib = [0u32; EXT2_N_BLOCKS];
        let mut icache = IndirectCache::new();
        let r = resolve_block(&cache, dev, &geom, &md, &ib, 5, Some(&mut icache)).unwrap();
        assert_eq!(r, None);
        assert!(icache.is_empty());
    }

    #[test]
    fn cache_mru_promotes_hit_to_front() {
        let mut c = IndirectCache::new();
        c.insert(1, 100);
        c.insert(2, 200);
        c.insert(3, 300);
        // Hit on entry 1 → promotes to front.
        assert_eq!(c.lookup(1), Some(100));
        // Now fill to capacity + 1; the eviction victim must be 2
        // (oldest), not 1 (just promoted).
        for k in 10..(10 + IndirectCache::CAPACITY as u32 - 2) {
            c.insert(k, k * 10);
        }
        // At this point we've inserted 3 + (CAP - 2) = CAP + 1 → one
        // eviction has already happened; victim was logical=2.
        assert_eq!(c.lookup(2), None);
        assert_eq!(c.lookup(1), Some(100));
        assert_eq!(c.lookup(3), Some(300));
    }
}
