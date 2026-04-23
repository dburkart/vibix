//! ext2 orphan-list final-close sequence (issue #573).
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Orphan list,
//! §Final-close sequence is the normative spec. Workstream E.
//!
//! # What this wave does
//!
//! When an unlinked-but-still-open inode reaches its last close (the
//! last non-orphan-list strong reference drops), the driver must run
//! the four-step finalize sequence:
//!
//! 1. **Truncate-to-zero**: free every data + indirect block via
//!    [`super::balloc::free_block`]; matches the shrinking-SIZE path in
//!    [`super::setattr::truncate_free`] (#572). Runs even for
//!    directories (which `setattr` refuses with `EISDIR`) — an orphaned
//!    empty directory may still own its data block until finalize
//!    releases it.
//! 2. **Unchain from the on-disk orphan list and stamp the tombstone**:
//!    update the predecessor that points at this ino (via
//!    `s_last_orphan` or another orphan's `i_dtime`) to skip over it,
//!    then stamp this inode's `i_dtime` with the current wall-clock
//!    time. This step **must** land before step 3 — see below.
//! 3. **Free the inode**: call [`super::ialloc::free_inode`] to clear
//!    the inode bitmap bit and bump `s_free_inodes_count`. Ordering
//!    unchain-before-free is load-bearing: once the bitmap bit is
//!    cleared, a concurrent `create(2)` can reallocate the ino. If
//!    unchain ran after free, the allocator could hand the ino to a new
//!    inode before the tombstone `i_dtime` write landed — and the
//!    orphan-chain walk would then either rewrite the new inode's
//!    `i_dtime` or leave `s_last_orphan` transiently pointing at a
//!    reallocated, non-orphan inode. Doing unchain first keeps those
//!    two worlds (orphan chain vs. live allocation) disjoint.
//! 4. **Drop the `Arc<Inode>` pin** from
//!    [`super::inode::OrphanList`]. This releases the residency root;
//!    any still-live cache `Weak<Inode>` will upgrade to `None` on the
//!    next `iget` and the cache slot gets swept out.
//!
//! # Atomicity
//!
//! If the driver crashes (or power cuts) mid-sequence, the on-mount
//! orphan-chain validator (#564) re-discovers the inode and pins it
//! into [`super::inode::OrphanList`]; a subsequent explicit
//! [`finalize`] call (or the equivalent userspace `fsck`) then re-runs
//! the sequence. The steps are ordered so each individual write leaves
//! the filesystem in a re-runnable state:
//!
//! - After step 1, blocks that were freed back to the allocator won't
//!   be double-freed on replay because step 1 rereads the current
//!   on-disk `i_block[]` each time — already-cleared slots are no-ops.
//! - Step 2 unchains the inode and stamps a real `i_dtime`. The bitmap
//!   bit is still set at this point, so the ino is not reusable; if we
//!   crash between step 2 and step 3, mount-replay (#564) observes
//!   `i_links_count == 0 && i_dtime != 0` — the canonical "fully
//!   deleted" state — and skips it. The orphan chain has already been
//!   patched, so the inode is no longer on any orphan-list walk.
//! - Step 3 (`free_inode`) tolerates a second call only if the bitmap
//!   bit is still set. A crash between the tombstone and this step
//!   leaves the bit set; mount-replay re-runs `free_inode` (the ino is
//!   not on the chain anymore, so replay finds it via a separate scan
//!   of the bitmap or via userspace `fsck`). The double-free is
//!   avoided because step 2's `i_dtime` stamp (a nonzero wall-clock)
//!   is what the replay validator checks to decide "this is fully
//!   deleted, skip."
//! - Step 4 is in-memory only; a crash here costs nothing beyond the
//!   pin until the next mount.
//!
//! # Out of scope
//!
//! - The production trigger (wiring the last-fd-close event to this
//!   finalize call). In the current ext2 driver, the orphan list holds
//!   `Arc<Inode>` strong refs — the last `OpenFile` drop doesn't cause
//!   the `Inode` to hit zero while an orphan-list entry exists.
//!   [`Ext2Super::evict_inode`](super::fs::Ext2Super) is the hook site
//!   the VFS `gc_queue` drives, but it only fires when the VFS drops
//!   the last `Arc<Inode>` it holds, which only happens after the
//!   orphan-list pin is explicitly released. Until the production
//!   trigger is wired (follow-up issue; see "Wiring the production
//!   trigger" below), callers invoke [`finalize`] directly — this is
//!   sufficient for the mount-time replay path (#564) and for the
//!   integration tests that exercise the sequence end-to-end.
//!
//! # Wiring the production trigger
//!
//! The RFC 0004 design envisions a per-`OpenFile` drop that, after
//! decrementing a driver-side refcount, calls this module's [`finalize`]
//! when the count hits zero for an unlinked inode. That refcount hook
//! doesn't exist yet on `OpenFile`; adding it is a separate VFS surface
//! change and will be handled in a follow-up. Until then, mount-time
//! replay (#564) and explicit calls (from tests, or a future background
//! orphan-sweep) are the two callers.

use alloc::sync::Arc;

use super::disk::{
    Ext2Inode as DiskInode, Ext2SuperBlock, EXT2_INODE_SIZE_V0, EXT2_N_BLOCKS, EXT2_SUPERBLOCK_SIZE,
};
use super::fs::{Ext2MountFlags, Ext2Super, SUPERBLOCK_BYTE_OFFSET};
use super::inode::Ext2Inode;
use super::setattr::{locate_inode_slot, truncate_free};

use crate::fs::{EIO, ENOENT, EROFS};

/// Run the RFC 0004 §Final-close sequence for orphan inode `ino` on
/// the given mount.
///
/// Preconditions (enforced by returns, not panic):
///
/// - The mount is writable (`EROFS` if `RDONLY` / `FORCED_RDONLY`).
/// - `ino` is present in [`super::inode::OrphanList`] (`ENOENT`
///   otherwise — an idempotent sentinel for "already finalized").
/// - The on-disk inode slot is still in the "orphan" state —
///   `i_links_count == 0`. A nonzero `i_links_count` means someone
///   relinked the inode while it was orphaned (e.g. `linkat(2)` against
///   an orphan, which ext2 does not currently permit but should reject
///   gracefully anyway); `EIO` is returned.
///
/// On success, the `Arc<Inode>` pin is removed from
/// [`super::inode::OrphanList`] and all of the on-disk bookkeeping is
/// flushed through the buffer cache.
///
/// On any mid-sequence error, the in-memory `orphan_list` pin is left
/// in place so the next finalize attempt (explicit re-call, or
/// mount-time replay) can retry.
pub fn finalize(super_ref: &Arc<Ext2Super>, ino: u32) -> Result<(), i64> {
    if super_ref.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_ref.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    // 0. Pull the pinned Arc<Inode> out of the orphan list as a clone
    //    so we can resolve the Ext2Inode + kind while the sequence
    //    runs. Do NOT remove the entry yet — keep the pin until step 4
    //    so a mid-sequence failure leaves the inode still recoverable.
    let pinned = {
        let list = super_ref.orphan_list.lock();
        list.get(&ino).cloned()
    };
    let pinned = pinned.ok_or(ENOENT)?;

    // Recover the driver-private Ext2Inode via the parallel cache.
    let ext2_inode = {
        let cache = super_ref.ext2_inode_cache.lock();
        cache.get(&ino).and_then(|w| w.upgrade()).ok_or(EIO)?
    };

    // Guard: the on-disk slot must still be in the orphan state —
    // `i_links_count == 0`. A racing relink (currently rejected by the
    // driver, but defense in depth) would leave a positive link count;
    // freeing the inode underneath a live dirent would silently corrupt
    // the filesystem. Read-only check, no lock held across it; the
    // orphan-list pin (cloned above) keeps the ino from being concurrently
    // finalized elsewhere.
    {
        let (disk, _, _) = read_disk_inode(super_ref, ino)?;
        if disk.i_links_count != 0 {
            return Err(EIO);
        }
    }

    // `free_inode`'s `was_dir` flag drives a `bg_used_dirs_count`
    // decrement. The unlink path (#569) already decrements that counter
    // inside `rmdir` via `decrement_used_dirs`, *before* it hands the
    // inode to the orphan list. Passing `was_dir = true` here would
    // double-decrement and leave the BGDT slot underflowed. The counter
    // is maintained at unlink time in this driver, not at finalize time.
    let was_dir = false;

    // 1. Truncate to zero: free all data + indirect blocks. Reuse the
    //    setattr shrinking path; it already walks reverse-logical so a
    //    crash mid-walk leaves a prefix reachable (not a suffix past
    //    EOF). `truncate_free` returns the updated i_block[] and the
    //    count of freed blocks; we commit both to disk via an RMW of
    //    the inode slot so that a crash between here and step 2 leaves
    //    the inode cleanly truncated (i_size=0, i_blocks=0, i_block[]
    //    all zero) — mount-replay (#564) will then re-run steps 2-4.
    truncate_inode_to_zero(super_ref, &ext2_inode)?;

    // 2. Remove this ino from the on-disk orphan chain and stamp the
    //    deletion tombstone. This **must** happen before step 3: once
    //    the inode bitmap bit is cleared, a concurrent `create(2)` can
    //    re-allocate this ino. Doing unchain-then-stamp first keeps the
    //    ino off the orphan chain and durably tombstoned while the bit
    //    is still set, so there's no window where `s_last_orphan` or a
    //    predecessor's `i_dtime` could transiently point at a reallocated,
    //    non-orphan inode.
    unchain_orphan(super_ref, ino)?;

    // 3. Free the inode number in the inode bitmap and bump
    //    `s_free_inodes_count`. `was_dir` decrements
    //    `bg_used_dirs_count` for the owning group.
    super::ialloc::free_inode(super_ref, ino, was_dir)?;

    // 4. Drop the in-memory Arc<Inode> pin. After this the inode cache's
    //    Weak<Inode> will no longer upgrade; a racing `iget` that
    //    started before step 4 may still hold a live Arc through its
    //    own local, and the tail of its walk will simply find a
    //    fully-deleted on-disk inode — which it should already tolerate
    //    via the `i_mode == 0` / `i_dtime != 0` decode check.
    {
        let mut list = super_ref.orphan_list.lock();
        let _ = list.remove(&ino);
    }

    drop(pinned);
    Ok(())
}

/// Step 1 of the finalize sequence: free every data + indirect block
/// on `ext2_inode`, zero out `i_block[]` / `i_blocks` / `i_size` in the
/// in-memory meta, and RMW-flush the on-disk inode slot.
///
/// A separate entry point (instead of invoking `setattr` with
/// `SIZE = 0`) because `setattr` refuses SIZE on directories (`EISDIR`)
/// — orphaned directories reach this path through rmdir's hit-zero,
/// and their data block (the last dirent page) must still be released.
/// This helper bypasses the kind-guard; it trusts the caller's
/// orphan-state proof.
fn truncate_inode_to_zero(
    super_ref: &Arc<Ext2Super>,
    ext2_inode: &Arc<Ext2Inode>,
) -> Result<(), i64> {
    // Snapshot the current i_block[] under the read lock; we pass it
    // into `truncate_free` without holding the lock across the (many)
    // buffer-cache writes the free walk will drive.
    let cur_i_block = { ext2_inode.meta.read().i_block };

    // new_size = 0 → free everything; `truncate_free` returns the
    // updated pointer array (all zeros on success) and a freed count.
    let (_freed, new_i_block) = truncate_free(super_ref, &cur_i_block, 0)?;

    // Apply to the in-memory meta.
    {
        let mut meta = ext2_inode.meta.write();
        meta.size = 0;
        meta.i_blocks = 0;
        meta.i_block = new_i_block;
    }

    // RMW the on-disk inode slot so a later mount-replay sees a
    // consistent zero-length orphan. We preserve `i_links_count` (must
    // stay 0 — the orphan invariant) and `i_dtime` (still the orphan-
    // chain next-pointer at this point; step 2 will overwrite it).
    let (block_in_dev, offset_in_block) = locate_inode_slot(super_ref, ext2_inode.ino)?;
    let bh = super_ref
        .cache
        .bread(super_ref.device_id, block_in_dev)
        .map_err(|_| EIO)?;
    {
        let mut data = bh.data.write();
        if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
            return Err(EIO);
        }
        let slot = &mut data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0];
        let mut disk = DiskInode::decode(slot);
        disk.i_size = 0;
        // On regular files with RO_COMPAT_LARGE_FILE, i_dir_acl_or_size_high
        // is the high 32 bits of size; clear it so size reads back as 0.
        let is_reg = (disk.i_mode & 0o170_000) == 0o100_000;
        if is_reg {
            disk.i_dir_acl_or_size_high = 0;
        }
        disk.i_blocks = 0;
        disk.i_block = [0u32; EXT2_N_BLOCKS];
        disk.encode_to_slot(slot);
    }
    super_ref.cache.mark_dirty(&bh);
    super_ref.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Step 2: remove `ino` from the on-disk orphan chain and stamp its
/// `i_dtime` tombstone.
///
/// The chain is a singly-linked list threaded through on-disk
/// `i_dtime` fields, with the head in `s_last_orphan`. To remove
/// `ino`:
///
/// - Read `ino`'s `i_dtime` — this is the *next* pointer in the chain.
/// - Walk from the head; find the predecessor whose next-pointer is
///   `ino` (or notice that `s_last_orphan == ino`).
/// - Patch the predecessor to point at `ino`'s next.
/// - Stamp `ino`'s on-disk `i_dtime` with the current wall-clock time
///   — converting the orphan-chain next-pointer into a real deletion
///   timestamp, which is what `e2fsck` and mount-replay (#564) use to
///   distinguish "fully deleted" from "still on the orphan list."
fn unchain_orphan(super_ref: &Arc<Ext2Super>, ino: u32) -> Result<(), i64> {
    let _guard = super_ref.alloc_mutex.lock();

    // Read `ino`'s current i_dtime (= next-pointer in the chain).
    let next_ptr = {
        let (disk, _, _) = read_disk_inode(super_ref, ino)?;
        disk.i_dtime
    };

    // Walk from the head to find the predecessor.
    let head = super_ref.sb_disk.lock().s_last_orphan;
    if head == 0 {
        // Chain is empty but caller claims `ino` is on it — the
        // in-memory orphan_list disagrees with the on-disk state.
        // Return EIO; the finalize call site will leave the pin and
        // a future replay can re-assess.
        return Err(EIO);
    }

    if head == ino {
        // `ino` is the head. Update `s_last_orphan := next_ptr` and
        // flush the superblock.
        let mut sb = super_ref.sb_disk.lock();
        sb.s_last_orphan = next_ptr;
        flush_superblock(super_ref, &sb)?;
    } else {
        // Walk forward. Bound by `s_inodes_count` to reject any
        // cycle a racing corruption might have introduced; in a
        // well-behaved chain the bound is never hit.
        let s_inodes_count = super_ref.sb_disk.lock().s_inodes_count;
        let mut cur = head;
        let mut steps: u32 = 0;
        loop {
            if steps > s_inodes_count {
                return Err(EIO);
            }
            steps += 1;
            // Fetch cur's next-pointer.
            let (cur_disk, _, _) = read_disk_inode(super_ref, cur)?;
            let cur_next = cur_disk.i_dtime;
            if cur_next == ino {
                // Predecessor: patch its i_dtime to `next_ptr`.
                rmw_disk_inode(super_ref, cur, |d| {
                    d.i_dtime = next_ptr;
                })?;
                break;
            }
            if cur_next == 0 {
                // End of chain without finding `ino` — inconsistent
                // state between the in-memory pin and the on-disk
                // chain. Return EIO; the pin is preserved for a
                // later retry.
                return Err(EIO);
            }
            cur = cur_next;
        }
    }

    // Finally, stamp `ino`'s own i_dtime with the wall-clock. The
    // on-disk inode slot was previously zeroed of its data pointers in
    // step 1 — this write converts the orphan-chain next-pointer into
    // a real deletion timestamp. Step 3 (`free_inode`) runs after this
    // to release the bitmap bit; at that point mount-replay sees
    // `i_links_count == 0 && i_dtime != 0` and knows the inode is
    // fully deleted.
    let now = crate::fs::vfs::Timespec::now().sec as u32;
    // `now == 0` would look like "still on orphan list" to the
    // mount-replay walker. Defend against a clock-at-epoch situation
    // (e.g. an early-boot RTC read returning 0) by substituting 1.
    let dtime_stamp = if now == 0 { 1 } else { now };
    rmw_disk_inode(super_ref, ino, |d| {
        d.i_dtime = dtime_stamp;
    })?;

    Ok(())
}

/// Mirrors the unlink.rs helper of the same name. Reads the 128-byte
/// rev-0 prefix of `ino`'s inode-table slot and returns the decoded
/// `DiskInode` plus the (block, offset_in_block) locating it for the
/// subsequent RMW.
fn read_disk_inode(super_: &Arc<Ext2Super>, ino: u32) -> Result<(DiskInode, u64, usize), i64> {
    let (block_in_dev, offset_in_block) = locate_inode_slot(super_, ino)?;
    let bh = super_
        .cache
        .bread(super_.device_id, block_in_dev)
        .map_err(|_| EIO)?;
    let data = bh.data.read();
    if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
        return Err(EIO);
    }
    let mut slot = [0u8; EXT2_INODE_SIZE_V0];
    slot.copy_from_slice(&data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0]);
    Ok((DiskInode::decode(&slot), block_in_dev, offset_in_block))
}

/// RMW an on-disk inode slot with `writer` and sync the block. Mirrors
/// `unlink::rmw_disk_inode` — kept as a module-local so each mutator
/// owns its own flush boundary.
fn rmw_disk_inode<F>(super_: &Arc<Ext2Super>, ino: u32, writer: F) -> Result<(), i64>
where
    F: FnOnce(&mut DiskInode),
{
    let (mut disk, block_in_dev, offset_in_block) = read_disk_inode(super_, ino)?;
    writer(&mut disk);
    let bh = super_
        .cache
        .bread(super_.device_id, block_in_dev)
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

/// Flush the in-memory `sb_disk` snapshot back to its on-disk slot.
/// Mirrors `unlink::flush_superblock` — each module owns its own copy
/// so mutators don't depend on sibling-module visibility.
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

// Host-side tests would need a full BlockCache + Ext2Super fixture; the
// end-to-end coverage lives in `kernel/tests/ext2_orphan_finalize.rs`
// under the ext2 integration harness.
