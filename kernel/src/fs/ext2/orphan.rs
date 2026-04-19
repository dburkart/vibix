//! Mount-time orphan-chain validation (issue #564).
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Orphan list is
//! the normative spec. On disk ext2 threads a singly-linked list of
//! unlinked-but-still-open inodes through the superblock's
//! [`s_last_orphan`](super::disk::Ext2SuperBlock::s_last_orphan) head;
//! each on-chain inode stores the next ino in its
//! [`i_dtime`](super::disk::Ext2Inode::i_dtime) slot (the field is
//! reused because an orphan isn't fully deleted yet — its real dtime is
//! zero while it's on the list). A previous mount can crash or lose
//! power mid-unlink and leave the chain populated; a malicious image
//! can forge a cycle, a self-loop, or an entry pointing at a reserved
//! inode number.
//!
//! This module is the defensive walk that runs inside
//! [`super::fs::Ext2Fs::mount`] **after** the block-group descriptor
//! table has been read and **before** the VFS sees the mount. The walk
//! is bounded at `s_inodes_count` iterations (anything longer is a
//! cycle or corruption), rejects any ino outside
//! `EXT2_ROOT_INO ∪ [s_first_ino, s_inodes_count]`, and detects cycles
//! via a seen-set indexed by ino. On any corruption the driver forces
//! the mount read-only (via [`ForceRo::Yes`]) and leaves the chain
//! alone — a user-space `fsck` is what repairs the on-disk state; the
//! kernel's job is only to refuse to scribble on a filesystem it can't
//! trust.
//!
//! # Out of scope
//!
//! - Draining (RW replay): freeing truncated-to-zero inodes back to the
//!   allocator. The allocator itself is Workstream E (#565+); until
//!   that lands the orphan-chain validator pins surviving entries into
//!   the in-memory [`super::inode::OrphanList`] so their blocks remain
//!   reserved for the life of the mount. On unmount the list drops
//!   (`Arc<Inode>` refcount hits zero) and the entries are implicitly
//!   re-orphaned on the next mount — the on-disk chain is never
//!   modified by this pass.
//! - Orphan-add / orphan-remove during runtime unlink: that's
//!   Workstream E's unlink/rmdir path (#565+). The map this pass
//!   populates is the same [`super::inode::OrphanList`] the unlink
//!   path will push into at runtime.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::disk::{
    Ext2Inode as DiskInode, Ext2SuperBlock, EXT2_GOOD_OLD_FIRST_INO, EXT2_INODE_SIZE_V0,
    EXT2_ROOT_INO,
};
use super::fs::Ext2Super;
use super::inode::iget;

use crate::block::cache::{BlockCache, DeviceId};
use crate::fs::vfs::super_block::SuperBlock;
use crate::{kinfo, kwarn};

/// Outcome of a mount-time orphan-chain walk.
///
/// [`ForceRo::No`] means the chain was consistent and (if nonempty) its
/// surviving entries are now pinned in
/// [`Ext2Super::orphan_list`](super::inode::Ext2Super::orphan_list).
/// [`ForceRo::Yes`] means the chain was corrupt (cycle, out-of-range
/// ino, reserved ino, non-orphan state) and the mount must be forced
/// to read-only — the caller ORs [`SbFlags::RDONLY`] into the mount's
/// effective flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForceRo {
    /// Chain was consistent; proceed with the caller-requested flags.
    No,
    /// Chain was corrupt; demote the mount to read-only and log.
    Yes,
}

/// Error classes that force the mount read-only. Returned from
/// [`classify_corruption`] and surfaced by [`validate_orphan_chain`]
/// via `kwarn!`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Corruption {
    /// Next-pointer pointed at an inode number outside
    /// `[1, s_inodes_count]` or into the reserved range (ino in
    /// `1..EXT2_GOOD_OLD_FIRST_INO` other than `EXT2_ROOT_INO`).
    OutOfRange,
    /// A node already visited in this walk — the chain has a cycle.
    Cycle,
    /// Walked more than `s_inodes_count` entries without terminating.
    /// Distinguished from [`Corruption::Cycle`] because the seen-set
    /// check is by-ino and a degenerate "N distinct inos all on the
    /// chain plus one extra hop" image would still hit the bound
    /// rather than the seen-set.
    LengthExceeded,
    /// The on-disk inode for a chain entry wasn't in a valid orphan
    /// state (`i_links_count > 0` with `i_dtime == 0`, or the read
    /// itself failed with EIO).
    NotOrphan,
}

/// Decide whether `ino` is a legal next-pointer in the orphan chain.
///
/// Legal inos are `EXT2_ROOT_INO` (2, because the root is in the
/// reserved range but is the one caller-visible reserved inode) and
/// any ino in `[EXT2_GOOD_OLD_FIRST_INO, s_inodes_count]`. Everything
/// else — ino 0 (the chain terminator, checked by the walk loop
/// before this helper), ino 1 (`EXT2_BAD_INO`), and the journal /
/// resize reservations in `3..=10` — is rejected.
///
/// Note that ino 0 is specifically **not** handled here — the walk
/// loop treats it as the chain terminator and breaks out before
/// calling this. Passing ino 0 is a programmer error; we still return
/// `false` to be safe.
#[inline]
fn is_valid_orphan_ino(ino: u32, s_inodes_count: u32) -> bool {
    if ino == 0 {
        return false;
    }
    if ino > s_inodes_count {
        return false;
    }
    if ino == EXT2_ROOT_INO {
        // Root on the orphan list is technically legal under the
        // on-disk format, even if nothing sane ever puts it there.
        // Accept so we match Linux's lenient parse.
        return true;
    }
    if ino < EXT2_GOOD_OLD_FIRST_INO {
        // Reserved range (1, 3..=10). Reject.
        return false;
    }
    true
}

/// Read the 128-byte rev-0 prefix of the on-disk inode slot for
/// `ino`, without constructing any VFS-layer state. Replays the
/// per-group + block-in-table arithmetic from
/// [`super::inode::iget`] because the walk needs to see `i_dtime` /
/// `i_links_count` for inodes whose `i_mode` may be zero — a
/// just-unlinked orphan typically has `i_mode == 0` once its dtime is
/// stamped, which `iget` would reject.
///
/// Returns `None` on any geometry / I/O error; the caller treats this
/// as [`Corruption::NotOrphan`] and force-ROs the mount.
fn read_disk_inode(
    cache: &BlockCache,
    device_id: DeviceId,
    sb_disk: &Ext2SuperBlock,
    bgdt: &[super::disk::Ext2GroupDesc],
    inode_size: u32,
    block_size: u32,
    ino: u32,
) -> Option<DiskInode> {
    if ino == 0 || ino > sb_disk.s_inodes_count {
        return None;
    }
    let inodes_per_group = sb_disk.s_inodes_per_group;
    if inodes_per_group == 0 {
        return None;
    }
    let group = (ino - 1) / inodes_per_group;
    let index_in_group = (ino - 1) % inodes_per_group;
    let group_idx = group as usize;
    if group_idx >= bgdt.len() {
        return None;
    }
    let bg = &bgdt[group_idx];

    let byte_offset = (index_in_group as u64) * (inode_size as u64);
    let block_in_table = byte_offset / (block_size as u64);
    let offset_in_block = (byte_offset % (block_size as u64)) as usize;
    let absolute_block = (bg.bg_inode_table as u64).checked_add(block_in_table)?;

    let bh = cache.bread(device_id, absolute_block).ok()?;
    let data = bh.data.read();
    if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
        return None;
    }
    let mut slot = [0u8; EXT2_INODE_SIZE_V0];
    slot.copy_from_slice(&data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0]);
    Some(DiskInode::decode(&slot))
}

/// Classify an on-disk inode read during the orphan walk.
///
/// A valid orphan has `i_links_count == 0` and some nonzero `i_mode`
/// (the mode stays set while the inode is still open — Linux only
/// zeroes it after the last close). The next-pointer lives in
/// `i_dtime` until the chain is drained. Anything else is treated as
/// corruption and the walk is aborted with [`Corruption::NotOrphan`].
///
/// Return value is the chain's next pointer (the on-disk `i_dtime`),
/// to be consumed by the walk loop. A terminator (next == 0) ends
/// the walk normally.
fn classify_orphan_state(disk: &DiskInode) -> Result<u32, Corruption> {
    if disk.i_links_count != 0 {
        return Err(Corruption::NotOrphan);
    }
    Ok(disk.i_dtime)
}

/// Walk the on-disk orphan list and pin any surviving entries into the
/// in-memory [`super::inode::OrphanList`].
///
/// Contract:
///
/// - Returns [`ForceRo::No`] on a clean walk (empty chain or all
///   entries pinned successfully).
/// - Returns [`ForceRo::Yes`] on any detected corruption; the walk
///   is aborted at the first bad node, a warning is `kwarn!`'d, and
///   the caller is expected to OR `SbFlags::RDONLY` into the mount's
///   effective flags. The on-disk chain is not modified either way.
/// - Never panics on a corrupt image. Bounded by `s_inodes_count`
///   iterations; cycle-detected via a seen-set.
///
/// The caller provides the freshly-built `Arc<Ext2Super>` and the
/// `Arc<SuperBlock>` *before* `SuperBlock::root` is populated —
/// [`iget`] doesn't consult `sb.root`, so this is safe. The pins are
/// inserted into `super_ref.orphan_list` keyed by ino; duplicates
/// (would only happen on a cycle, which we already reject) are
/// ignored defensively.
pub fn validate_orphan_chain(super_ref: &Arc<Ext2Super>, sb: &Arc<SuperBlock>) -> ForceRo {
    let (decision, drained) = walk_orphan_chain(super_ref);
    if decision == ForceRo::Yes {
        return ForceRo::Yes;
    }
    if drained.is_empty() {
        return ForceRo::No;
    }
    pin_orphans(super_ref, sb, &drained);
    ForceRo::No
}

/// Phase 1 of the mount-time orphan walk: pure read-only traversal of
/// the on-disk chain, producing the list of surviving orphan inos and
/// a [`ForceRo`] verdict.
///
/// Split out from [`validate_orphan_chain`] so the caller can run the
/// walk **before** building the `Arc<SuperBlock>` — a corrupt chain
/// needs to flip the sb's `RDONLY` flag, which is immutable after
/// `SuperBlock::new`. The caller phase-2s the pinning after building
/// the sb, via [`pin_orphans`].
pub fn walk_orphan_chain(super_ref: &Arc<Ext2Super>) -> (ForceRo, Vec<u32>) {
    walk_orphan_chain_raw(
        &super_ref.cache,
        super_ref.device_id,
        &super_ref.sb_disk,
        &super_ref.bgdt,
        super_ref.inode_size,
        super_ref.block_size,
    )
}

/// Dependency-lean variant of [`walk_orphan_chain`] that consumes only
/// the raw block-layer + on-disk-state pieces rather than an assembled
/// `Arc<Ext2Super>`. Called from the mount path before the
/// `Ext2Super` / `SuperBlock` pair has been constructed; a corrupt
/// chain has to flip the effective `RDONLY` flag *before* the
/// `SuperBlock` is built (its `SbFlags` is immutable post-construction).
pub fn walk_orphan_chain_raw(
    cache: &BlockCache,
    device_id: DeviceId,
    sb_disk: &Ext2SuperBlock,
    bgdt: &[super::disk::Ext2GroupDesc],
    inode_size: u32,
    block_size: u32,
) -> (ForceRo, Vec<u32>) {
    let head = sb_disk.s_last_orphan;
    if head == 0 {
        // Fast path: no chain to walk. The vast majority of cleanly-
        // unmounted images hit this branch.
        return (ForceRo::No, Vec::new());
    }

    let s_inodes_count = sb_disk.s_inodes_count;
    // Bound: any chain longer than the total number of inodes must
    // contain a repeat. Use `as usize` for the Vec-based seen-set;
    // ext2 tops out at u32::MAX inodes which fits fine.
    let max_walk = s_inodes_count as usize;
    // Seen-set: BitVec indexed by ino. Sized to s_inodes_count + 1 so
    // ino `s_inodes_count` itself is addressable (inos are 1-based).
    // Allocating a Vec<bool> rather than a packed bitset keeps this
    // module standalone; a 64 KiB fixture is 16 bytes here, and even
    // a 4M-inode filesystem is only 4 MiB — allocated once at mount
    // and dropped immediately after.
    let mut seen: Vec<bool> = vec![false; (s_inodes_count as usize) + 1];

    let mut cur = head;
    let mut drained: Vec<u32> = Vec::new();

    for _step in 0..=max_walk {
        if cur == 0 {
            // Normal terminator. The list walked cleanly.
            break;
        }
        if !is_valid_orphan_ino(cur, s_inodes_count) {
            kwarn!(
                "ext2: orphan chain: ino {} out of range (reserved or >= s_inodes_count), forcing RO",
                cur,
            );
            return (ForceRo::Yes, Vec::new());
        }
        let cur_idx = cur as usize;
        if seen[cur_idx] {
            kwarn!(
                "ext2: orphan chain: cycle detected at ino {}, forcing RO",
                cur,
            );
            return (ForceRo::Yes, Vec::new());
        }
        seen[cur_idx] = true;

        let disk =
            match read_disk_inode(cache, device_id, sb_disk, bgdt, inode_size, block_size, cur) {
                Some(d) => d,
                None => {
                    kwarn!(
                        "ext2: orphan chain: unreadable inode {} during walk, forcing RO",
                        cur,
                    );
                    return (ForceRo::Yes, Vec::new());
                }
            };
        let next = match classify_orphan_state(&disk) {
            Ok(n) => n,
            Err(e) => {
                // `classify_orphan_state` only ever returns
                // `Corruption::NotOrphan` today; the other
                // `Corruption` variants are produced by the walk loop
                // (range check, cycle, length-exceeded) above and
                // don't reach this arm. Match all for forward-
                // compat so any new variant added to the enum forces
                // an explicit handling decision here.
                match e {
                    Corruption::NotOrphan => kwarn!(
                        "ext2: orphan chain: inode {} has i_links_count={} != 0 (not an orphan), forcing RO",
                        cur,
                        disk.i_links_count,
                    ),
                    Corruption::OutOfRange
                    | Corruption::Cycle
                    | Corruption::LengthExceeded => kwarn!(
                        "ext2: orphan chain: inode {} classified as corrupt ({:?}), forcing RO",
                        cur,
                        e,
                    ),
                }
                return (ForceRo::Yes, Vec::new());
            }
        };

        drained.push(cur);
        cur = next;
    }

    // If the loop exited on the bound instead of hitting a 0 terminator
    // or a seen-set hit, the chain is still too long. The `_step` loop
    // runs `0..=max_walk` iterations (max_walk + 1), so reaching the
    // end with cur != 0 means we walked at least s_inodes_count + 1
    // distinct inos — impossible without a cycle the seen-set somehow
    // missed, or without the image claiming more inodes than it can
    // address. Either way: corruption.
    if cur != 0 {
        let _ = Corruption::LengthExceeded; // keep the variant reachable for future refactors
        kwarn!(
            "ext2: orphan chain: exceeded s_inodes_count={} without terminator, forcing RO",
            s_inodes_count,
        );
        return (ForceRo::Yes, Vec::new());
    }

    (ForceRo::No, drained)
}

/// Phase 2 of the mount-time orphan walk: pin each surviving orphan
/// ino into `super_ref.orphan_list` as an `Arc<Inode>` so its data
/// blocks remain reserved for the life of the mount.
///
/// Separate from [`walk_orphan_chain`] so the caller can run the walk
/// before building `Arc<SuperBlock>` (the sb's `RDONLY` flag needs to
/// be settled before construction — it's immutable afterwards), then
/// run this phase against the built sb.
///
/// An `iget` failure here downgrades to a warning rather than
/// force-ROing the mount: the raw read already confirmed the slot
/// looked orphan-ish, and we don't want a late-phase failure to
/// retroactively tear down a mount the caller has already committed
/// to. The cost of a skipped pin is "blocks might get reallocated on
/// a later write" — only matters on RW mounts, and full allocator
/// drain is Workstream E territory.
pub fn pin_orphans(super_ref: &Arc<Ext2Super>, sb: &Arc<SuperBlock>, inos: &[u32]) {
    if inos.is_empty() {
        return;
    }
    let mut list = super_ref.orphan_list.lock();
    let mut pinned = 0usize;
    for ino in inos {
        match iget(super_ref, sb, *ino) {
            Ok(inode) => {
                list.entry(*ino).or_insert(inode);
                pinned += 1;
            }
            Err(e) => {
                kwarn!(
                    "ext2: orphan chain: could not iget surviving orphan {} (errno={}), skipping pin",
                    *ino,
                    e,
                );
            }
        }
    }
    kinfo!(
        "ext2: orphan chain: pinned {} surviving orphan(s) from s_last_orphan",
        pinned,
    );
}

#[cfg(test)]
mod tests {
    //! Host-side unit tests for the pure-logic helpers. The full walk
    //! is covered by `kernel/tests/ext2_orphan_chain.rs` which drives
    //! the real mount path against crafted in-memory images.
    use super::*;

    #[test]
    fn valid_orphan_ino_accepts_root_and_user_range() {
        // Root is the one reserved ino we accept.
        assert!(is_valid_orphan_ino(EXT2_ROOT_INO, 1024));
        // User-allocatable range.
        assert!(is_valid_orphan_ino(EXT2_GOOD_OLD_FIRST_INO, 1024));
        assert!(is_valid_orphan_ino(12, 1024));
        assert!(is_valid_orphan_ino(1024, 1024));
    }

    #[test]
    fn valid_orphan_ino_rejects_zero_reserved_and_oob() {
        // Zero is the terminator, not a legal next-pointer here.
        assert!(!is_valid_orphan_ino(0, 1024));
        // EXT2_BAD_INO and the 3..=10 journal / resize reservations.
        assert!(!is_valid_orphan_ino(1, 1024));
        assert!(!is_valid_orphan_ino(3, 1024));
        assert!(!is_valid_orphan_ino(10, 1024));
        // Past s_inodes_count.
        assert!(!is_valid_orphan_ino(1025, 1024));
        assert!(!is_valid_orphan_ino(u32::MAX, 1024));
    }

    #[test]
    fn classify_orphan_state_reads_next_pointer_on_links_zero() {
        let disk = DiskInode {
            i_mode: 0o100_644,
            i_uid: 0,
            i_size: 0,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            // i_dtime carries the next-pointer while on the orphan list.
            i_dtime: 42,
            i_gid: 0,
            i_links_count: 0,
            i_blocks: 0,
            i_flags: 0,
            i_block: [0u32; super::super::disk::EXT2_N_BLOCKS],
            i_dir_acl_or_size_high: 0,
            l_i_uid_high: 0,
            l_i_gid_high: 0,
        };
        assert_eq!(classify_orphan_state(&disk), Ok(42));
    }

    #[test]
    fn classify_orphan_state_rejects_live_inode() {
        let disk = DiskInode {
            i_mode: 0o100_644,
            i_uid: 0,
            i_size: 0,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_dtime: 42,
            i_gid: 0,
            // i_links_count > 0 → not an orphan; walk must refuse.
            i_links_count: 1,
            i_blocks: 0,
            i_flags: 0,
            i_block: [0u32; super::super::disk::EXT2_N_BLOCKS],
            i_dir_acl_or_size_high: 0,
            l_i_uid_high: 0,
            l_i_gid_high: 0,
        };
        assert_eq!(classify_orphan_state(&disk), Err(Corruption::NotOrphan));
    }
}
