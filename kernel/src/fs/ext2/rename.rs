//! ext2 rename — `InodeOps::rename` with link-count-first ordering and
//! a cross-directory ancestor (loop) check (issue #571).
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Rename ordering
//! and §Cross-directory loop check are the normative specs. Workstream E.
//!
//! # Normative ordering
//!
//! A rename mutates up to four inodes (old parent, new parent, source,
//! optional victim) in one logical step. The on-disk sequence is
//! strictly **link-count-first**:
//!
//! 1. Bump `source.i_links_count` (now >= 2).
//! 2. If a victim exists at `new_name`, remove its dirent and decrement
//!    its `i_links_count`.
//! 3. Insert the new dirent in `new_parent` pointing at `source.ino`.
//!    At this point both `old_name` and `new_name` resolve to the
//!    source inode — the "both-names-visible" crash-safe window.
//! 4. Remove the old dirent in `old_parent`.
//! 5. Decrement `source.i_links_count` back to its original value.
//! 6. Victim finalisation: if the victim's count hit zero, push it on
//!    the on-disk orphan list so `e2fsck` (or the final-close path,
//!    #573) can reclaim its blocks.
//! 7. Cross-dir directory move: update source's `..` dirent to point
//!    at `new_parent`, bump `new_parent.i_links_count`, decrement
//!    `old_parent.i_links_count`.
//!
//! A crash at any point before step 4 leaves both names live — worst
//! case a hard-link that `e2fsck` tidies. A crash between steps 4 and 5
//! leaves `source.i_links_count` one too high — `e2fsck` reconciles.
//! The filesystem never observes the "dirent points at inode that's
//! been freed" window that a dirent-first order would expose (RFC 0004
//! §Security).
//!
//! # Cross-directory ancestor check
//!
//! Moving a directory across parents must refuse renames into its own
//! subtree; otherwise the resulting `..` chain would be cyclic and a
//! user-level walker would loop forever. We walk from `new_parent` up
//! to the filesystem root via each directory's `..` dirent; if the
//! source's ino appears anywhere on the chain (or equals `new_parent`
//! itself), return `EINVAL` — the POSIX error for rename-into-subtree.
//!
//! (The RFC calls this "ELOOP" in prose; POSIX dictates `EINVAL`. We
//! return `EINVAL` to match POSIX and Linux's VFS layer — `path_walk`
//! reserves `ELOOP` for symlink chains.)
//!
//! # Scope
//!
//! - `RENAME_EXCHANGE` / `RENAME_WHITEOUT`: out of scope (RFC 0004
//!   §Out of scope). The VFS syscall layer (already merged as #541)
//!   rejects these flags before reaching here.
//! - `RENAME_NOREPLACE`: the syscall-layer flag is plumbed through the
//!   trait via a dedicated helper only when a future PR grows the
//!   trait signature; today it's enforced by refusing destination-
//!   exists at the syscall layer. This module does implement atomic
//!   replace so that a future noreplace helper can share the path.

use alloc::sync::Arc;

use super::disk::{
    EXT2_FT_BLKDEV, EXT2_FT_CHRDEV, EXT2_FT_DIR, EXT2_FT_FIFO, EXT2_FT_REG_FILE, EXT2_FT_SOCK,
    EXT2_FT_SYMLINK,
};
use super::fs::{Ext2MountFlags, Ext2Super};
use super::inode::{iget, Ext2Inode};
use super::unlink::{
    decrement_used_dirs, dir_is_empty, ext2_inode_from_vfs, locate_dirent, now_secs,
    push_on_orphan_list, remove_dirent_at, resolve_sb_for_super, rmw_disk_inode,
};

use crate::fs::vfs::inode::{Inode, InodeKind};
use crate::fs::{EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY, EROFS};

use core::sync::atomic::Ordering;

/// POSIX-advertised ceiling on the depth of a directory tree we'll
/// walk looking for an ancestry match. `EXT2_LINK_MAX` is 32000 but
/// real trees are shallow; a few hundred levels is a practical guard
/// that refuses pathological cyclic images without allocating a set.
const ANCESTOR_WALK_MAX: u32 = 4096;

/// Map a VFS `InodeKind` to an ext2 `EXT2_FT_*` value for dirent
/// insertion. Mirrors the table in `create::NewNode::file_type`, kept
/// as a free function so rename (which doesn't know at compile time
/// what kind of inode it's re-linking) can call it.
fn ext2_ftype(kind: InodeKind) -> u8 {
    match kind {
        InodeKind::Reg => EXT2_FT_REG_FILE,
        InodeKind::Dir => EXT2_FT_DIR,
        InodeKind::Link => EXT2_FT_SYMLINK,
        InodeKind::Chr => EXT2_FT_CHRDEV,
        InodeKind::Blk => EXT2_FT_BLKDEV,
        InodeKind::Fifo => EXT2_FT_FIFO,
        InodeKind::Sock => EXT2_FT_SOCK,
    }
}

/// Walk from `start_ino` up the `..` chain to the root, returning
/// `Ok(true)` if `target_ino` appears anywhere on the walk (including
/// at `start_ino`), `Ok(false)` if we reach the root without matching.
///
/// Used by cross-dir directory rename to refuse
/// rename-into-own-subtree: passing `target = source_ino` and
/// `start = new_parent_ino`.
///
/// # Errors
///
/// - `EIO` — a `..` entry is missing, points outside the fs, or a
///   walk step exceeds `ANCESTOR_WALK_MAX`.
fn is_ancestor(super_: &Arc<Ext2Super>, target_ino: u32, start_ino: u32) -> Result<bool, i64> {
    let mut cur = start_ino;
    for _ in 0..ANCESTOR_WALK_MAX {
        if cur == target_ino {
            return Ok(true);
        }
        // `/` is ino 2 on ext2; its `..` points at itself. Terminate
        // the walk when we reach it without matching.
        if cur == super::disk::EXT2_ROOT_INO {
            return Ok(false);
        }
        // Load `cur`'s Ext2Inode and look up `..` in it. We need a
        // Weak<SuperBlock> chain for iget, which resolve_sb_for_super
        // recovers via the inode cache.
        let sb = resolve_sb_for_super(super_)?;
        let arc = iget(super_, &sb, cur)?;
        let ext2 = ext2_inode_from_vfs(super_, &arc).ok_or(EIO)?;
        let parent_ino = super::dir::lookup(super_, &ext2, b"..")?;
        if parent_ino == 0 || parent_ino == cur {
            // Either a corrupt `..` (ino 0) or a self-loop at a non-
            // root node — stop walking without declaring a match. A
            // self-loop at root was handled above; here it's
            // filesystem corruption we don't want to spin on.
            return Ok(false);
        }
        cur = parent_ino;
    }
    Err(EIO)
}

/// Overwrite the `..` dirent in `dir` so it points at `new_parent_ino`.
/// Used when a directory is moved across parents. The `..` record is
/// always the second record in the dir's first data block (stamped by
/// `create::create_dir`), so we scan the first block for the dirent
/// whose name is `..` and RMW the `inode` field only — preserving
/// `rec_len` / `name_len` / `file_type`.
///
/// We cannot reuse [`locate_dirent`] here because it rejects `.` and
/// `..` as a safety rail for the unlink/rename name-validation paths
/// (where those names are always EINVAL). Here, `..` is exactly the
/// name we need.
fn rewrite_dotdot(
    super_: &Arc<Ext2Super>,
    dir: &Ext2Inode,
    new_parent_ino: u32,
) -> Result<(), i64> {
    use super::disk::{Ext2DirEntry2, EXT2_DIR_REC_HEADER_LEN};

    let block_size = super_.block_size;
    let (size, i_block) = {
        let meta = dir.meta.read();
        (meta.size, meta.i_block)
    };
    if size == 0 {
        return Err(EIO);
    }

    // The `..` record lives in the directory's first logical block.
    // `create::create_dir` stamps `.` then `..` there, and nothing in
    // the driver ever relocates them (ext2 never compacts dirents).
    let abs_block = i_block[0];
    if abs_block == 0 {
        return Err(EIO);
    }
    let bh = super_
        .cache
        .bread(super_.device_id, abs_block as u64)
        .map_err(|_| EIO)?;
    let logical_len = core::cmp::min(size, block_size as u64) as usize;

    // Locate the offset of the `..` record, then drop the read guard
    // before re-acquiring for write.
    let offset = {
        let data = bh.data.read();
        let end = core::cmp::min(data.len(), logical_len);
        let mut cursor = 0usize;
        let mut found: Option<usize> = None;
        while cursor < end {
            if end - cursor < EXT2_DIR_REC_HEADER_LEN {
                break;
            }
            let hdr = Ext2DirEntry2::decode_header(&data[cursor..cursor + EXT2_DIR_REC_HEADER_LEN]);
            let rec_len = hdr.rec_len as usize;
            if rec_len < EXT2_DIR_REC_HEADER_LEN || rec_len % 4 != 0 || cursor + rec_len > end {
                return Err(EIO);
            }
            if hdr.inode != 0 {
                let name_len = hdr.name_len as usize;
                let name_start = cursor + EXT2_DIR_REC_HEADER_LEN;
                let name_end = name_start + name_len;
                if name_end > cursor + rec_len {
                    return Err(EIO);
                }
                if &data[name_start..name_end] == b".." {
                    found = Some(cursor);
                    break;
                }
            }
            cursor += rec_len;
        }
        found.ok_or(EIO)?
    };

    {
        let mut data = bh.data.write();
        if offset + 4 > data.len() {
            return Err(EIO);
        }
        data[offset..offset + 4].copy_from_slice(&new_parent_ino.to_le_bytes());
    }
    super_.cache.mark_dirty(&bh);
    super_.cache.sync_dirty_buffer(&bh).map_err(|_| EIO)?;
    Ok(())
}

/// Core `rename` entry point invoked from `Ext2Inode`'s `InodeOps`
/// impl. `old_parent` / `new_parent` are the driver-private inode
/// handles; `old_parent_vfs` / `new_parent_vfs` are the VFS handles
/// the caller already holds (same identity as `inode.ops` dispatches
/// through; used to reach `dir_rwsem` + `sb.rename_mutex`).
pub fn rename(
    old_parent: &Ext2Inode,
    old_parent_vfs: &Inode,
    old_name: &[u8],
    new_parent: &Ext2Inode,
    new_parent_vfs: &Inode,
    new_name: &[u8],
) -> Result<(), i64> {
    let super_ = old_parent.super_ref.upgrade().ok_or(EIO)?;
    if super_.ext2_flags.contains(Ext2MountFlags::RDONLY)
        || super_.ext2_flags.contains(Ext2MountFlags::FORCED_RDONLY)
    {
        return Err(EROFS);
    }

    // Both parents must come from the same mount.
    {
        let new_super = new_parent.super_ref.upgrade().ok_or(EIO)?;
        if !Arc::ptr_eq(&super_, &new_super) {
            return Err(EIO);
        }
    }

    // Name validation. For rename, `.` and `..` on either side are
    // EINVAL per POSIX — the generic `validate_name` surfaces them
    // as EEXIST (right for create, wrong for rename), so we gate
    // those first and then let the shared validator take the
    // remaining cases (empty, NUL, `/`, too-long).
    if old_name == b"." || old_name == b".." || new_name == b"." || new_name == b".." {
        return Err(EINVAL);
    }
    super::create::validate_name(old_name)?;
    super::create::validate_name(new_name)?;

    let same_parent = old_parent.ino == new_parent.ino;
    // NB: the same-parent same-name "no-op" return moved *after*
    // `locate_dirent(old_name)` below — returning Ok(()) up here would
    // paper over a missing source (rename("missing","missing") must be
    // ENOENT, not success).

    // Acquire locks.
    //  - Cross-dir: take `sb.rename_mutex` first (global tiebreaker),
    //    then `dir_rwsem` on each parent in ino order.
    //  - Same-dir: one `dir_rwsem` write lock is enough.
    let sb_for_mutex = resolve_sb_for_super(&super_)?;
    let _rename_guard = if same_parent {
        None
    } else {
        Some(sb_for_mutex.rename_mutex.lock())
    };

    // Bind the rwsem guards to this frame. In the same-parent case
    // only one guard is taken; in the cross-parent case both, in
    // inode-number order to prevent ABBA deadlock against a
    // concurrent rename in the opposite direction.
    let (_g1, _g2) = if same_parent {
        (Some(old_parent_vfs.dir_rwsem.write()), None)
    } else if old_parent_vfs.ino < new_parent_vfs.ino {
        (
            Some(old_parent_vfs.dir_rwsem.write()),
            Some(new_parent_vfs.dir_rwsem.write()),
        )
    } else {
        (
            Some(new_parent_vfs.dir_rwsem.write()),
            Some(old_parent_vfs.dir_rwsem.write()),
        )
    };

    // 1. Locate the source dirent and load the source inode.
    let src_loc = locate_dirent(&super_, old_parent, old_name)?;
    // Now that we've proved `old_name` exists, a same-parent rename
    // onto the same name is a successful no-op.
    if same_parent && old_name == new_name {
        return Ok(());
    }
    let parent_sb = resolve_sb_for_super(&super_)?;
    let source_vfs = iget(&super_, &parent_sb, src_loc.child_ino)?;
    let source_ext2 = ext2_inode_from_vfs(&super_, &source_vfs).ok_or(EIO)?;
    let source_is_dir = source_vfs.kind == InodeKind::Dir;

    // 2. Cross-directory ancestor check for directory moves. A
    //    directory must not be renamed into itself or any of its
    //    descendants; otherwise the `..` chain becomes cyclic.
    if source_is_dir && !same_parent {
        if source_vfs.ino as u32 == new_parent.ino {
            return Err(EINVAL);
        }
        if is_ancestor(&super_, source_vfs.ino as u32, new_parent.ino)? {
            return Err(EINVAL);
        }
    }

    // 3. Probe for a victim at new_name.
    let victim = match locate_dirent(&super_, new_parent, new_name) {
        Ok(v) => Some(v),
        Err(e) if e == ENOENT => None,
        Err(e) => return Err(e),
    };

    // Resolve victim inode (if any) + enforce type/empty rules before
    // any mutation. If source == victim (e.g. same-dir case-preserving
    // rename) treat as no-op.
    let victim_arcs = if let Some(vloc) = victim.as_ref() {
        if vloc.child_ino == src_loc.child_ino {
            // Renaming a name onto itself (e.g. same dir, different
            // case on a case-sensitive FS but byte-identical). No-op.
            return Ok(());
        }
        let v_arc = iget(&super_, &parent_sb, vloc.child_ino)?;
        let v_ext2 = ext2_inode_from_vfs(&super_, &v_arc).ok_or(EIO)?;
        let victim_is_dir = v_arc.kind == InodeKind::Dir;
        match (source_is_dir, victim_is_dir) {
            (true, false) => return Err(ENOTDIR),
            (false, true) => return Err(EISDIR),
            _ => {}
        }
        if victim_is_dir && !dir_is_empty(&super_, &v_ext2)? {
            return Err(ENOTEMPTY);
        }
        Some((v_arc, v_ext2))
    } else {
        None
    };

    let now = now_secs();

    // 4. LINK-COUNT-FIRST: bump source links before touching any dirent.
    rmw_disk_inode(&super_, src_loc.child_ino, |disk| {
        disk.i_links_count = disk.i_links_count.saturating_add(1);
        disk.i_ctime = now;
    })?;
    {
        let mut meta = source_ext2.meta.write();
        meta.links_count = meta.links_count.saturating_add(1);
        meta.ctime = now;
    }
    {
        let mut vfs_meta = source_vfs.meta.write();
        vfs_meta.nlink = vfs_meta.nlink.saturating_add(1);
        vfs_meta.ctime = crate::fs::vfs::Timespec {
            sec: now as i64,
            nsec: 0,
        };
    }

    // 5. If a victim exists, strip its dirent + decrement its link
    //    count so the follow-up `add_link` can use (or newly
    //    allocate) a slot. Note: we intentionally leave the source's
    //    bumped links in place; the dirent for `new_name` doesn't
    //    exist yet, so source is only reachable through `old_name`
    //    at this instant — the bumped count represents the
    //    *about-to-be-added* second link.
    let mut victim_hit_zero: Option<u32> = None;
    if let (Some(vloc), Some((v_arc, v_ext2))) = (victim.as_ref(), victim_arcs.as_ref()) {
        remove_dirent_at(&super_, vloc)?;
        // rmdir semantics for a victim directory: links goes 2 -> 0
        // (both the self `.` and the parent-held `..` are gone).
        // Unlink semantics for a non-dir: links -= 1.
        let dec: u16 = if source_is_dir { 2 } else { 1 };
        let mut new_links: u16 = 0;
        rmw_disk_inode(&super_, vloc.child_ino, |disk| {
            disk.i_links_count = disk.i_links_count.saturating_sub(dec);
            disk.i_ctime = now;
            new_links = disk.i_links_count;
        })?;
        {
            let mut meta = v_ext2.meta.write();
            meta.links_count = meta.links_count.saturating_sub(dec);
            meta.ctime = now;
        }
        {
            let mut vfs_meta = v_arc.meta.write();
            let dec32 = dec as u32;
            vfs_meta.nlink = vfs_meta.nlink.saturating_sub(dec32);
            vfs_meta.ctime = crate::fs::vfs::Timespec {
                sec: now as i64,
                nsec: 0,
            };
        }
        // A victim directory replacement also costs `new_parent` one
        // nlink (it loses the victim's `..` back-link). The
        // incoming source directory will re-add it below if cross-
        // dir, or not at all if same-dir (source was already
        // contributing one nlink via its own `..`).
        if source_is_dir {
            rmw_disk_inode(&super_, new_parent.ino, |disk| {
                disk.i_links_count = disk.i_links_count.saturating_sub(1);
                disk.i_ctime = now;
            })?;
            {
                let mut meta = new_parent.meta.write();
                meta.links_count = meta.links_count.saturating_sub(1);
                meta.ctime = now;
            }
            {
                let mut vfs_meta = new_parent_vfs.meta.write();
                vfs_meta.nlink = vfs_meta.nlink.saturating_sub(1);
                vfs_meta.ctime = crate::fs::vfs::Timespec {
                    sec: now as i64,
                    nsec: 0,
                };
            }
        }
        if new_links == 0 {
            victim_hit_zero = Some(vloc.child_ino);
            // When the victim was a directory, its block group's
            // `bg_used_dirs_count` must be decremented — same as the
            // rmdir path does in `unlink.rs`. Without this the BGDT
            // directory counts drift after a directory-over-directory
            // rename.
            if source_is_dir {
                decrement_used_dirs(&super_, vloc.child_ino)?;
            }
        }
    }

    // 6. Insert the new dirent in new_parent. This is the
    //    both-names-visible moment — a crash between here and step 7
    //    leaves the source reachable through both names, which
    //    `e2fsck` resolves as a stray hard link (no corruption).
    let ftype = ext2_ftype(source_vfs.kind);
    super::create::add_link(&super_, new_parent, new_name, src_loc.child_ino, ftype)?;

    // 7. Remove the old dirent.
    //
    // Re-locate it first: `add_link` in step 6 almost certainly split
    // the slack of some record in `old_parent` (commonly the last
    // live record, which for same-dir rename is often the source
    // itself). That shrinks the original dirent's `rec_len`, so
    // `src_loc.rec_len` captured before the insert is stale. Using it
    // to extend the previous record would over-swallow past the newly
    // inserted record. Re-scanning costs one directory walk but keeps
    // the remove-step correct under every slack layout.
    let src_loc = locate_dirent(&super_, old_parent, old_name)?;
    remove_dirent_at(&super_, &src_loc)?;

    // 8. Restore source's link count by decrementing back to the
    //    original value.
    rmw_disk_inode(&super_, src_loc.child_ino, |disk| {
        disk.i_links_count = disk.i_links_count.saturating_sub(1);
        disk.i_ctime = now;
    })?;
    {
        let mut meta = source_ext2.meta.write();
        meta.links_count = meta.links_count.saturating_sub(1);
        meta.ctime = now;
    }
    {
        let mut vfs_meta = source_vfs.meta.write();
        vfs_meta.nlink = vfs_meta.nlink.saturating_sub(1);
        vfs_meta.ctime = crate::fs::vfs::Timespec {
            sec: now as i64,
            nsec: 0,
        };
    }

    // 9. Cross-directory directory move: rewrite `..`, shuffle the
    //    parent dirs' nlink counts. Intentionally runs after the
    //    link-count-first dance so a crash between step 7 and here
    //    leaves a cosmetic "wrong parent ino in `..`" that e2fsck
    //    fixes, not an unreachable inode.
    if source_is_dir && !same_parent {
        rewrite_dotdot(&super_, &source_ext2, new_parent.ino)?;
        // new_parent gains the `..` back-link from source.
        rmw_disk_inode(&super_, new_parent.ino, |disk| {
            disk.i_links_count = disk.i_links_count.saturating_add(1);
            disk.i_ctime = now;
        })?;
        {
            let mut meta = new_parent.meta.write();
            meta.links_count = meta.links_count.saturating_add(1);
            meta.ctime = now;
        }
        {
            let mut vfs_meta = new_parent_vfs.meta.write();
            vfs_meta.nlink = vfs_meta.nlink.saturating_add(1);
            vfs_meta.ctime = crate::fs::vfs::Timespec {
                sec: now as i64,
                nsec: 0,
            };
        }
        // old_parent loses the `..` back-link.
        rmw_disk_inode(&super_, old_parent.ino, |disk| {
            disk.i_links_count = disk.i_links_count.saturating_sub(1);
            disk.i_ctime = now;
        })?;
        {
            let mut meta = old_parent.meta.write();
            meta.links_count = meta.links_count.saturating_sub(1);
            meta.ctime = now;
        }
        {
            let mut vfs_meta = old_parent_vfs.meta.write();
            vfs_meta.nlink = vfs_meta.nlink.saturating_sub(1);
            vfs_meta.ctime = crate::fs::vfs::Timespec {
                sec: now as i64,
                nsec: 0,
            };
        }
    }

    // 10. Victim finalisation: if its links hit zero, push it on the
    //     orphan list so the final-close path (#573) can reclaim its
    //     blocks. The victim's dirent is already gone by step 5.
    if let Some(ino) = victim_hit_zero {
        if let Some((v_arc, v_ext2)) = victim_arcs.as_ref() {
            // Push-then-mark ordering: see the matching note in
            // `unlink::unlink_common` step 8 — the open-fd-close
            // finalize trigger (#638) reads `unlinked` then expects
            // the orphan_list pin to already be there.
            push_on_orphan_list(&super_, ino, v_arc)?;
            v_ext2.unlinked.store(true, Ordering::SeqCst);
        }
    }

    Ok(())
}
