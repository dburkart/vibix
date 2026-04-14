//! `ramfs` — read-write, `BTreeMap`-backed in-memory filesystem.
//!
//! Implements RFC 0002 item 6/15. Mounted at `/tmp` and used to
//! validate the full VFS op-vector end-to-end before any real disk FS
//! lands.
//!
//! ## Design
//!
//! Each inode carries an `Arc<BlockingMutex<RamfsBody>>` that holds
//! the FS-private mutable state alongside the standard `Inode.meta` /
//! `Inode.dir_rwsem` that the VFS layer owns. The three body variants
//! are:
//!
//! - `Reg { data: Vec<u8> }` — inline byte buffer.
//! - `Dir { children: BTreeMap<DString, Arc<Inode>> }` — directory.
//! - `Sym { target: Vec<u8> }` — symbolic-link target.
//!
//! Hardlinks are first-class: the `inode_table`
//! (`BTreeMap<u64, Weak<Inode>>`) ensures every lookup of the same
//! `(fs_id, ino)` pair returns the same `Arc<Inode>`, so `st_ino`
//! identity is stable across multiple dentries.
//!
//! ## Locking order
//!
//! To avoid deadlocks the following total order is observed:
//!
//! 1. `SuperBlock.rename_mutex` (outermost; cross-dir rename only).
//! 2. `Inode.dir_rwsem` (write for mutation, read for lookup).
//! 3. `Inode.meta` write lock (metadata update).
//! 4. `RamfsBody` lock (brief; no sleeps while held).
//! 5. `RamfsState.inode_table` lock (inode identity bookkeeping;
//!    held only to insert/remove — not during I/O).
//!
//! `read`/`write`/`seek`/`getdents` do **not** take `dir_rwsem`; they
//! operate exclusively on the body and/or `OpenFile.offset`.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::BlockingMutex;

use super::inode::{Inode, InodeKind, InodeMeta};
use super::mount_table::alloc_fs_id;
use super::open_file::OpenFile;
use super::ops::{
    meta_into_stat, FileOps, FileSystem, InodeOps, MountSource, SetAttr, SetAttrMask, Stat, StatFs,
    SuperOps, Whence,
};
use super::super_block::{SbFlags, SuperBlock};
use super::DString;

// ---------------------------------------------------------------------------
// Local errno values
// ---------------------------------------------------------------------------

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EISDIR: i64 = -21;
const ENOTDIR: i64 = -20;
const ENOTEMPTY: i64 = -39;
const EINVAL: i64 = -22;
const EXDEV: i64 = -18;

// RAMFS_MAGIC matches Linux's value.
const RAMFS_MAGIC: u64 = 0x858458f6;

// ---------------------------------------------------------------------------
// Per-inode body (mutable FS-private data)
// ---------------------------------------------------------------------------

pub(super) enum RamfsBody {
    Reg {
        data: Vec<u8>,
    },
    Dir {
        children: BTreeMap<DString, Arc<Inode>>,
    },
    Sym {
        target: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// Shared mount state
// ---------------------------------------------------------------------------

struct RamfsState {
    next_ino: AtomicU64,
    /// Identity table so all lookups of the same ino return the same
    /// `Arc<Inode>` (required for stable `st_ino` across hardlinks).
    inode_table: BlockingMutex<BTreeMap<u64, Weak<Inode>>>,
}

impl RamfsState {
    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    fn track(&self, inode: &Arc<Inode>) {
        self.inode_table
            .lock()
            .insert(inode.ino, Arc::downgrade(inode));
    }

    fn untrack(&self, ino: u64) {
        self.inode_table.lock().remove(&ino);
    }

    fn get(&self, ino: u64) -> Option<Arc<Inode>> {
        self.inode_table.lock().get(&ino).and_then(Weak::upgrade)
    }
}

// ---------------------------------------------------------------------------
// Per-inode InodeOps + FileOps carrier
// ---------------------------------------------------------------------------

/// Implements both `InodeOps` and `FileOps` for a single inode.
/// Carries the body and the shared mount state via `Arc` so it can be
/// cloned into both the `ops` and `file_ops` fields of `Inode`.
struct RamfsInode {
    body: Arc<BlockingMutex<RamfsBody>>,
    state: Arc<RamfsState>,
}

/// Helper: retrieve the `Arc<BlockingMutex<RamfsBody>>` from any
/// `Arc<dyn InodeOps>` that is concretely a `RamfsInode`. Because
/// `no_std` has no `Any` downcast, we cast through the fat-pointer
/// data pointer.
///
/// # Safety
/// Only called on inodes that were created by `alloc_inode()` in this
/// module, which always stores an `Arc<RamfsInode>` in `ops` and
/// `file_ops`. All inodes in a ramfs mount satisfy this invariant.
fn body_of_ops(ops: &Arc<dyn InodeOps>) -> &Arc<BlockingMutex<RamfsBody>> {
    // SAFETY: Every inode created by this module stores Arc<RamfsInode>
    // as Arc<dyn InodeOps>. The fat-pointer data component points to the
    // RamfsInode allocation. We recover it by going through `*const ()`
    // (the standard idiom for erasing vtable from a fat pointer) and then
    // casting to *const RamfsInode.
    //
    // Soundness requirements:
    //   1. Arc<RamfsInode> lives at least as long as Arc<dyn InodeOps>.
    //   2. We never write through the resulting reference.
    //   3. Only called within this module on inodes we created.
    let data_ptr: *const () = Arc::as_ptr(ops) as *const ();
    let raw: *const RamfsInode = data_ptr as *const RamfsInode;
    unsafe { &(*raw).body }
}

// ---------------------------------------------------------------------------
// Allocate a new inode
// ---------------------------------------------------------------------------

fn alloc_inode(
    sb: &Arc<SuperBlock>,
    state: &Arc<RamfsState>,
    kind: InodeKind,
    mode: u16,
    nlink: u32,
    body: RamfsBody,
) -> Arc<Inode> {
    let ino = state.alloc_ino();
    let body_arc = Arc::new(BlockingMutex::new(body));
    let carrier = Arc::new(RamfsInode {
        body: body_arc,
        state: state.clone(),
    });
    let meta = InodeMeta {
        mode,
        nlink,
        blksize: 4096,
        ..Default::default()
    };
    let inode = Arc::new(Inode::new(
        ino,
        Arc::downgrade(sb),
        carrier.clone() as Arc<dyn InodeOps>,
        carrier as Arc<dyn FileOps>,
        kind,
        meta,
    ));
    state.track(&inode);
    inode
}

// ---------------------------------------------------------------------------
// InodeOps impl
// ---------------------------------------------------------------------------

impl InodeOps for RamfsInode {
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, i64> {
        let _guard = dir.dir_rwsem.read();
        let body = self.body.lock();
        match &*body {
            RamfsBody::Dir { children } => {
                let key = DString::try_from_bytes(name).map_err(|_| ENOENT)?;
                children.get(&key).cloned().ok_or(ENOENT)
            }
            _ => Err(ENOTDIR),
        }
    }

    fn create(&self, dir: &Inode, name: &[u8], mode: u16) -> Result<Arc<Inode>, i64> {
        let sb = dir.sb.upgrade().ok_or(ENOENT)?;
        let _guard = dir.dir_rwsem.write();
        let key = DString::try_from_bytes(name)?;
        {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Dir { children } if children.contains_key(&key) => {
                    return Err(crate::fs::EEXIST);
                }
                RamfsBody::Dir { .. } => {}
                _ => return Err(ENOTDIR),
            }
        }
        let child = alloc_inode(
            &sb,
            &self.state,
            InodeKind::Reg,
            mode & 0o7777,
            1,
            RamfsBody::Reg { data: Vec::new() },
        );
        self.body
            .lock()
            .as_dir_mut()
            .unwrap()
            .insert(key, child.clone());
        Ok(child)
    }

    fn mkdir(&self, dir: &Inode, name: &[u8], mode: u16) -> Result<Arc<Inode>, i64> {
        let sb = dir.sb.upgrade().ok_or(ENOENT)?;
        let _guard = dir.dir_rwsem.write();
        let key = DString::try_from_bytes(name)?;
        {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Dir { children } if children.contains_key(&key) => {
                    return Err(crate::fs::EEXIST);
                }
                RamfsBody::Dir { .. } => {}
                _ => return Err(ENOTDIR),
            }
        }
        let child = alloc_inode(
            &sb,
            &self.state,
            InodeKind::Dir,
            mode & 0o7777,
            2, // self-link + ".."
            RamfsBody::Dir {
                children: BTreeMap::new(),
            },
        );
        self.body
            .lock()
            .as_dir_mut()
            .unwrap()
            .insert(key, child.clone());
        // Parent gains a back-link from the new subdir's "..".
        {
            let mut meta = dir.meta.write();
            meta.nlink = meta.nlink.saturating_add(1);
        }
        Ok(child)
    }

    fn unlink(&self, dir: &Inode, name: &[u8]) -> Result<(), i64> {
        let _guard = dir.dir_rwsem.write();
        let key = DString::try_from_bytes(name).map_err(|_| ENOENT)?;
        let child = {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Dir { children } => children.get(&key).cloned().ok_or(ENOENT)?,
                _ => return Err(ENOTDIR),
            }
        };
        if child.kind == InodeKind::Dir {
            return Err(EISDIR);
        }
        self.body.lock().as_dir_mut().unwrap().remove(&key);
        let new_nlink = {
            let mut meta = child.meta.write();
            meta.nlink = meta.nlink.saturating_sub(1);
            meta.nlink
        };
        if new_nlink == 0 {
            child.state.lock().unlinked = true;
        }
        Ok(())
    }

    fn rmdir(&self, dir: &Inode, name: &[u8]) -> Result<(), i64> {
        let _guard = dir.dir_rwsem.write();
        let key = DString::try_from_bytes(name).map_err(|_| ENOENT)?;
        let child = {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Dir { children } => children.get(&key).cloned().ok_or(ENOENT)?,
                _ => return Err(ENOTDIR),
            }
        };
        if child.kind != InodeKind::Dir {
            return Err(ENOTDIR);
        }
        // Verify target is empty. Access the child's body via its ops.
        {
            let child_body_arc = body_of_ops(&child.ops);
            let child_body = child_body_arc.lock();
            match &*child_body {
                RamfsBody::Dir { children } if !children.is_empty() => {
                    return Err(ENOTEMPTY);
                }
                _ => {}
            }
        }
        self.body.lock().as_dir_mut().unwrap().remove(&key);
        {
            let mut meta = child.meta.write();
            meta.nlink = 0;
        }
        child.state.lock().unlinked = true;
        // Parent loses the ".." link from the removed subdir.
        {
            let mut meta = dir.meta.write();
            meta.nlink = meta.nlink.saturating_sub(1);
        }
        Ok(())
    }

    fn rename(
        &self,
        old_dir: &Inode,
        old_name: &[u8],
        new_dir: &Inode,
        new_name: &[u8],
    ) -> Result<(), i64> {
        let sb = old_dir.sb.upgrade().ok_or(ENOENT)?;
        {
            let new_sb = new_dir.sb.upgrade().ok_or(ENOENT)?;
            if !Arc::ptr_eq(&sb, &new_sb) {
                return Err(EXDEV);
            }
        }
        let _rename_lock = sb.rename_mutex.lock();

        let old_key = DString::try_from_bytes(old_name)?;
        let new_key = DString::try_from_bytes(new_name)?;

        let same_dir = core::ptr::eq(old_dir as *const Inode, new_dir as *const Inode);

        if same_dir {
            let _guard = old_dir.dir_rwsem.write();
            // Renaming to the same name is always a successful no-op.
            if old_key == new_key {
                return Ok(());
            }
            let mut body = self.body.lock();
            let children = match &mut *body {
                RamfsBody::Dir { children } => children,
                _ => return Err(ENOTDIR),
            };
            let moving = children.get(&old_key).cloned().ok_or(ENOENT)?;
            // Check for non-empty directory displacement.
            if let Some(existing) = children.get(&new_key) {
                if existing.kind == InodeKind::Dir {
                    if moving.kind != InodeKind::Dir {
                        return Err(EISDIR);
                    }
                    let ex_body_arc = body_of_ops(&existing.ops);
                    let ex_body = ex_body_arc.lock();
                    if let RamfsBody::Dir { children: c } = &*ex_body {
                        if !c.is_empty() {
                            return Err(ENOTEMPTY);
                        }
                    }
                    drop(ex_body);
                    // Replacing a dir: adjust nlink for old dir.
                    let displaced = children.remove(&new_key).unwrap();
                    displaced.meta.write().nlink = 0;
                    displaced.state.lock().unlinked = true;
                    // Same dir — no parent nlink change needed.
                } else if moving.kind == InodeKind::Dir {
                    // Trying to rename a dir over a non-dir: ENOTDIR.
                    return Err(ENOTDIR);
                } else {
                    let displaced = children.remove(&new_key).unwrap();
                    let new_nlink = {
                        let mut m = displaced.meta.write();
                        m.nlink = m.nlink.saturating_sub(1);
                        m.nlink
                    };
                    if new_nlink == 0 {
                        displaced.state.lock().unlinked = true;
                    }
                }
            }
            children.remove(&old_key);
            children.insert(new_key, moving);
        } else {
            // Cross-directory rename: lock in ino order.
            let (first_rwsem, second_rwsem, first_is_old) = if old_dir.ino < new_dir.ino {
                (&old_dir.dir_rwsem, &new_dir.dir_rwsem, true)
            } else {
                (&new_dir.dir_rwsem, &old_dir.dir_rwsem, false)
            };
            let _g1 = first_rwsem.write();
            let _g2 = second_rwsem.write();

            let old_body_arc = body_of_ops(&old_dir.ops);
            let new_body_arc = body_of_ops(&new_dir.ops);

            let moving = {
                let mut ob = old_body_arc.lock();
                match &mut *ob {
                    RamfsBody::Dir { children } => children.get(&old_key).cloned().ok_or(ENOENT)?,
                    _ => return Err(ENOTDIR),
                }
            };

            {
                let mut nb = new_body_arc.lock();
                match &mut *nb {
                    RamfsBody::Dir { children } => {
                        // Validate and handle displaced target (mirror same-dir checks).
                        if let Some(existing) = children.get(&new_key).cloned() {
                            if existing.kind == InodeKind::Dir {
                                if moving.kind != InodeKind::Dir {
                                    return Err(EISDIR);
                                }
                                let ex_body_arc = body_of_ops(&existing.ops);
                                let ex_body = ex_body_arc.lock();
                                if let RamfsBody::Dir { children: c } = &*ex_body {
                                    if !c.is_empty() {
                                        return Err(ENOTEMPTY);
                                    }
                                }
                                drop(ex_body);
                                let displaced = children.remove(&new_key).unwrap();
                                displaced.meta.write().nlink = 0;
                                displaced.state.lock().unlinked = true;
                                let mut meta = new_dir.meta.write();
                                meta.nlink = meta.nlink.saturating_sub(1);
                            } else if moving.kind == InodeKind::Dir {
                                return Err(ENOTDIR);
                            } else {
                                let displaced = children.remove(&new_key).unwrap();
                                let new_nlink = {
                                    let mut m = displaced.meta.write();
                                    m.nlink = m.nlink.saturating_sub(1);
                                    m.nlink
                                };
                                if new_nlink == 0 {
                                    displaced.state.lock().unlinked = true;
                                }
                            }
                        }
                        children.insert(new_key, moving.clone());
                    }
                    _ => return Err(ENOTDIR),
                }
            }

            {
                let mut ob = old_body_arc.lock();
                if let RamfsBody::Dir { children } = &mut *ob {
                    children.remove(&old_key);
                }
            }

            // Adjust parent nlinks for moved subdirectory.
            if moving.kind == InodeKind::Dir {
                {
                    let mut meta = old_dir.meta.write();
                    meta.nlink = meta.nlink.saturating_sub(1);
                }
                {
                    let mut meta = new_dir.meta.write();
                    meta.nlink = meta.nlink.saturating_add(1);
                }
            }
            let _ = first_is_old; // used only for documentation
        }
        Ok(())
    }

    fn link(&self, dir: &Inode, name: &[u8], target: &Inode) -> Result<(), i64> {
        if target.kind == InodeKind::Dir {
            return Err(EPERM);
        }
        // Reject cross-superblock hardlinks before inode-table lookup.
        let dir_sb = dir.sb.upgrade().ok_or(ENOENT)?;
        let target_sb = target.sb.upgrade().ok_or(ENOENT)?;
        if !Arc::ptr_eq(&dir_sb, &target_sb) {
            return Err(EXDEV);
        }
        let _guard = dir.dir_rwsem.write();
        let key = DString::try_from_bytes(name)?;
        {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Dir { children } if children.contains_key(&key) => {
                    return Err(crate::fs::EEXIST);
                }
                RamfsBody::Dir { .. } => {}
                _ => return Err(ENOTDIR),
            }
        }
        // Look up the canonical Arc<Inode> from the identity table.
        let inode_arc = self.state.get(target.ino).ok_or(ENOENT)?;
        self.body
            .lock()
            .as_dir_mut()
            .unwrap()
            .insert(key, inode_arc);
        {
            let mut meta = target.meta.write();
            meta.nlink = meta.nlink.saturating_add(1);
        }
        Ok(())
    }

    fn symlink(&self, dir: &Inode, name: &[u8], target: &[u8]) -> Result<Arc<Inode>, i64> {
        let sb = dir.sb.upgrade().ok_or(ENOENT)?;
        let _guard = dir.dir_rwsem.write();
        let key = DString::try_from_bytes(name)?;
        {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Dir { children } if children.contains_key(&key) => {
                    return Err(crate::fs::EEXIST);
                }
                RamfsBody::Dir { .. } => {}
                _ => return Err(ENOTDIR),
            }
        }
        let child = alloc_inode(
            &sb,
            &self.state,
            InodeKind::Link,
            0o777,
            1,
            RamfsBody::Sym {
                target: target.to_vec(),
            },
        );
        self.body
            .lock()
            .as_dir_mut()
            .unwrap()
            .insert(key, child.clone());
        Ok(child)
    }

    fn readlink(&self, _inode: &Inode, buf: &mut [u8]) -> Result<usize, i64> {
        let body = self.body.lock();
        match &*body {
            RamfsBody::Sym { target } => {
                let n = target.len().min(buf.len());
                buf[..n].copy_from_slice(&target[..n]);
                Ok(n)
            }
            _ => Err(EINVAL),
        }
    }

    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let sb = inode.sb.upgrade().ok_or(ENOENT)?;
        let size = {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Reg { data } => data.len() as u64,
                RamfsBody::Sym { target } => target.len() as u64,
                RamfsBody::Dir { .. } => 0,
            }
        };
        inode.meta.write().size = size;
        let meta = inode.meta.read();
        meta_into_stat(&meta, inode.kind, sb.fs_id.0, inode.ino, out);
        Ok(())
    }

    fn setattr(&self, inode: &Inode, attr: &SetAttr) -> Result<(), i64> {
        if attr.mask.contains(SetAttrMask::SIZE) {
            let mut body = self.body.lock();
            if let RamfsBody::Reg { data } = &mut *body {
                data.resize(attr.size as usize, 0);
            }
        }
        let mut meta = inode.meta.write();
        if attr.mask.contains(SetAttrMask::MODE) {
            meta.mode = attr.mode;
        }
        if attr.mask.contains(SetAttrMask::UID) {
            meta.uid = attr.uid;
        }
        if attr.mask.contains(SetAttrMask::GID) {
            meta.gid = attr.gid;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileOps impl
// ---------------------------------------------------------------------------

impl FileOps for RamfsInode {
    fn read(&self, _f: &OpenFile, buf: &mut [u8], off: u64) -> Result<usize, i64> {
        let body = self.body.lock();
        match &*body {
            RamfsBody::Reg { data } => {
                let start = (off as usize).min(data.len());
                let n = (data.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&data[start..start + n]);
                Ok(n)
            }
            RamfsBody::Dir { .. } => Err(EISDIR),
            RamfsBody::Sym { .. } => Err(EINVAL),
        }
    }

    fn write(&self, f: &OpenFile, buf: &[u8], off: u64) -> Result<usize, i64> {
        let mut body = self.body.lock();
        match &mut *body {
            RamfsBody::Reg { data } => {
                let start = off as usize;
                let end = start + buf.len();
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[start..end].copy_from_slice(buf);
                drop(body);
                f.inode.meta.write().size = end as u64;
                Ok(buf.len())
            }
            RamfsBody::Dir { .. } => Err(EISDIR),
            RamfsBody::Sym { .. } => Err(EINVAL),
        }
    }

    fn seek(&self, f: &OpenFile, whence: Whence, off: i64) -> Result<u64, i64> {
        let mut cur = f.offset.lock();
        let size = {
            let body = self.body.lock();
            match &*body {
                RamfsBody::Reg { data } => data.len() as i64,
                RamfsBody::Dir { children } => children.len() as i64,
                RamfsBody::Sym { target } => target.len() as i64,
            }
        };
        let new_off = match whence {
            Whence::Set => off,
            Whence::Cur => (*cur as i64).saturating_add(off),
            Whence::End => size.saturating_add(off),
        };
        if new_off < 0 {
            return Err(EINVAL);
        }
        *cur = new_off as u64;
        Ok(*cur)
    }

    fn getdents(&self, f: &OpenFile, buf: &mut [u8], cookie: &mut u64) -> Result<usize, i64> {
        // `cookie` is the count of virtual entries already consumed.
        // Virtual entries:  index 0 = ".",  index 1 = "..",  2+ = children.
        // BTreeMap iteration order is stable (sorted by DString), so
        // skipping by count is equivalent to "last returned name" as
        // described in the RFC.
        let inode = &f.inode;
        let _guard = inode.dir_rwsem.read();
        let body = self.body.lock();
        let children = match &*body {
            RamfsBody::Dir { children } => children,
            _ => return Err(-20i64), // ENOTDIR
        };

        let dir_ino = inode.ino;
        // Without traversing parent dentries, use the same ino for "..".
        // Callers that need accurate parent ino use path_walk instead.
        let parent_ino = dir_ino;

        let mut written = 0usize;
        let mut idx: u64 = 0;

        macro_rules! emit {
            ($ino:expr, $d_type:expr, $name:expr) => {{
                if idx >= *cookie {
                    let consumed = emit_dirent(buf, written, $ino, idx + 1, $d_type, $name);
                    if consumed == 0 {
                        *cookie = idx;
                        return Ok(written);
                    }
                    written += consumed;
                }
                idx += 1;
            }};
        }

        emit!(dir_ino, 4u8, b"." as &[u8]);
        emit!(parent_ino, 4u8, b".." as &[u8]);

        for (name, child) in children.iter() {
            emit!(child.ino, inode_kind_to_dt(child.kind), name.as_bytes());
        }

        *cookie = idx;
        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// linux_dirent64 emission helper
// ---------------------------------------------------------------------------

/// Emits one `linux_dirent64` record at `buf[offset..]`.
/// Returns the number of bytes written, or 0 if the buffer has no room.
fn emit_dirent(
    buf: &mut [u8],
    offset: usize,
    d_ino: u64,
    d_off: u64,
    d_type: u8,
    name: &[u8],
) -> usize {
    // linux_dirent64:
    //   u64  d_ino        (offset 0)
    //   i64  d_off        (offset 8)
    //   u16  d_reclen     (offset 16)
    //   u8   d_type       (offset 18)
    //   char d_name[]     (offset 19, NUL-terminated, padded to 8-byte alignment)
    let header = 19usize;
    let raw = header + name.len() + 1; // +1 for NUL
    let reclen = (raw + 7) & !7; // round up to 8-byte boundary

    let dest = match buf.get_mut(offset..offset + reclen) {
        Some(s) => s,
        None => return 0,
    };

    dest.fill(0);
    dest[0..8].copy_from_slice(&d_ino.to_ne_bytes());
    dest[8..16].copy_from_slice(&d_off.to_ne_bytes());
    dest[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    dest[18] = d_type;
    dest[19..19 + name.len()].copy_from_slice(name);
    // NUL byte already zero from fill(0).

    reclen
}

fn inode_kind_to_dt(kind: InodeKind) -> u8 {
    match kind {
        InodeKind::Reg => 8,   // DT_REG
        InodeKind::Dir => 4,   // DT_DIR
        InodeKind::Link => 10, // DT_LNK
        InodeKind::Chr => 2,   // DT_CHR
        InodeKind::Blk => 6,   // DT_BLK
        InodeKind::Fifo => 1,  // DT_FIFO
        InodeKind::Sock => 12, // DT_SOCK
    }
}

// ---------------------------------------------------------------------------
// RamfsBody helpers
// ---------------------------------------------------------------------------

impl RamfsBody {
    fn as_dir_mut(&mut self) -> Option<&mut BTreeMap<DString, Arc<Inode>>> {
        match self {
            RamfsBody::Dir { children } => Some(children),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SuperOps impl
// ---------------------------------------------------------------------------

struct RamfsSuperOps {
    state: Arc<RamfsState>,
    sb: Weak<SuperBlock>,
}

impl SuperOps for RamfsSuperOps {
    fn root_inode(&self) -> Arc<Inode> {
        self.sb
            .upgrade()
            .expect("ramfs: SuperBlock dropped")
            .root
            .get()
            .expect("ramfs: root not initialized")
            .clone()
    }

    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs {
            f_type: RAMFS_MAGIC,
            f_bsize: 4096,
            f_namelen: super::NAME_MAX as u64,
            ..Default::default()
        })
    }

    fn unmount(&self) -> Result<(), i64> {
        Ok(()) // in-memory FS: nothing to flush
    }

    fn evict_inode(&self, ino: u64) -> Result<(), i64> {
        self.state.untrack(ino);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileSystem factory impl
// ---------------------------------------------------------------------------

/// `RamFs` — stateless factory. Register one instance globally;
/// each `mount()` call returns a fresh `SuperBlock` with its own state.
pub struct RamFs;

impl FileSystem for RamFs {
    fn name(&self) -> &'static str {
        "ramfs"
    }

    fn mount(
        &self,
        _source: MountSource<'_>,
        _flags: super::MountFlags,
    ) -> Result<Arc<SuperBlock>, i64> {
        let fs_id = alloc_fs_id();

        // Build the SuperBlock via `Arc::new_cyclic` so the `SuperOps`
        // and root `Inode` can hold `Weak<SuperBlock>` back-references.
        let sb = Arc::new_cyclic(|weak_sb: &Weak<SuperBlock>| {
            let state = Arc::new(RamfsState {
                next_ino: AtomicU64::new(2), // ino 1 = root
                inode_table: BlockingMutex::new(BTreeMap::new()),
            });

            let super_ops = Arc::new(RamfsSuperOps {
                state: state.clone(),
                sb: weak_sb.clone(),
            });

            let sb_inner = SuperBlock::new(
                fs_id,
                super_ops as Arc<dyn SuperOps>,
                "ramfs",
                4096,
                SbFlags::default(),
            );

            // Root inode: ino=1, dir, mode=0o755, nlink=2.
            let root = alloc_inode_with_ino(
                1,
                weak_sb,
                &state,
                InodeKind::Dir,
                0o755,
                2,
                RamfsBody::Dir {
                    children: BTreeMap::new(),
                },
            );
            sb_inner.root.call_once(|| root);
            sb_inner
        });

        Ok(sb)
    }
}

/// Like `alloc_inode` but uses a caller-supplied ino (for the root,
/// which has the reserved ino 1 rather than one from the counter).
fn alloc_inode_with_ino(
    ino: u64,
    weak_sb: &Weak<SuperBlock>,
    state: &Arc<RamfsState>,
    kind: InodeKind,
    mode: u16,
    nlink: u32,
    body: RamfsBody,
) -> Arc<Inode> {
    let carrier = Arc::new(RamfsInode {
        body: Arc::new(BlockingMutex::new(body)),
        state: state.clone(),
    });
    let meta = InodeMeta {
        mode,
        nlink,
        blksize: 4096,
        ..Default::default()
    };
    let inode = Arc::new(Inode::new(
        ino,
        weak_sb.clone(),
        carrier.clone() as Arc<dyn InodeOps>,
        carrier as Arc<dyn FileOps>,
        kind,
        meta,
    ));
    state.track(&inode);
    inode
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::dentry::Dentry;
    use crate::fs::vfs::open_file::OpenFile;
    use crate::fs::vfs::super_block::SbActiveGuard;
    use crate::fs::vfs::{MountFlags, MountSource};

    fn make_ramfs() -> Arc<SuperBlock> {
        RamFs
            .mount(MountSource::None, MountFlags::default())
            .expect("ramfs mount failed")
    }

    fn root_of(sb: &Arc<SuperBlock>) -> Arc<Inode> {
        sb.ops.root_inode()
    }

    fn open_inode(sb: &Arc<SuperBlock>, inode: Arc<Inode>) -> Arc<OpenFile> {
        let dentry = Dentry::new_root(inode.clone());
        let guard = SbActiveGuard::try_acquire(sb).expect("SbActiveGuard");
        OpenFile::new(
            dentry,
            inode.clone(),
            inode.file_ops.clone(),
            sb.clone(),
            0,
            guard,
        )
    }

    #[test]
    fn create_and_lookup() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.create(&root, b"hello", 0o644).expect("create");
        let found = root.ops.lookup(&root, b"hello").expect("lookup");
        assert_eq!(found.kind, InodeKind::Reg);
    }

    #[test]
    fn lookup_missing_is_enoent() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        assert_eq!(root.ops.lookup(&root, b"nope"), Err(ENOENT));
    }

    #[test]
    fn unlink_decrements_nlink() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.create(&root, b"f", 0o644).expect("create");
        let f = root.ops.lookup(&root, b"f").expect("lookup");
        assert_eq!(f.meta.read().nlink, 1);

        root.ops.link(&root, b"f2", &f).expect("link");
        assert_eq!(f.meta.read().nlink, 2);

        root.ops.unlink(&root, b"f").expect("unlink");
        assert_eq!(f.meta.read().nlink, 1);
        assert!(!f.state.lock().unlinked);

        root.ops.unlink(&root, b"f2").expect("unlink f2");
        assert_eq!(f.meta.read().nlink, 0);
        assert!(f.state.lock().unlinked);
    }

    #[test]
    fn mkdir_and_rmdir_nlink() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        assert_eq!(root.meta.read().nlink, 2);

        root.ops.mkdir(&root, b"sub", 0o755).expect("mkdir");
        assert_eq!(root.meta.read().nlink, 3);

        root.ops.rmdir(&root, b"sub").expect("rmdir");
        assert_eq!(root.meta.read().nlink, 2);
        assert_eq!(root.ops.lookup(&root, b"sub"), Err(ENOENT));
    }

    #[test]
    fn rmdir_notempty() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.mkdir(&root, b"dir", 0o755).expect("mkdir");
        let dir = root.ops.lookup(&root, b"dir").expect("lookup dir");
        dir.ops.create(&dir, b"file", 0o644).expect("create");
        assert_eq!(root.ops.rmdir(&root, b"dir"), Err(ENOTEMPTY));
    }

    #[test]
    fn rename_same_dir() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.create(&root, b"a", 0o644).expect("create");
        root.ops.rename(&root, b"a", &root, b"b").expect("rename");
        assert_eq!(root.ops.lookup(&root, b"a"), Err(ENOENT));
        assert!(root.ops.lookup(&root, b"b").is_ok());
    }

    #[test]
    fn rename_cross_dir() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.mkdir(&root, b"sub", 0o755).expect("mkdir");
        let sub = root.ops.lookup(&root, b"sub").expect("lookup sub");
        root.ops.create(&root, b"a", 0o644).expect("create a");
        root.ops
            .rename(&root, b"a", &sub, b"a")
            .expect("cross-dir rename");
        assert_eq!(root.ops.lookup(&root, b"a"), Err(ENOENT));
        assert!(sub.ops.lookup(&sub, b"a").is_ok());
    }

    #[test]
    fn symlink_and_readlink() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops
            .symlink(&root, b"lnk", b"/etc/passwd")
            .expect("symlink");
        let lnk = root.ops.lookup(&root, b"lnk").expect("lookup lnk");
        assert_eq!(lnk.kind, InodeKind::Link);
        let mut buf = [0u8; 64];
        let n = lnk.ops.readlink(&lnk, &mut buf).expect("readlink");
        assert_eq!(&buf[..n], b"/etc/passwd");
    }

    #[test]
    fn write_read_roundtrip() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        let child = root.ops.create(&root, b"data", 0o644).expect("create");
        let file = open_inode(&sb, child.clone());
        let payload = b"hello world";
        let n = child.file_ops.write(&file, payload, 0).expect("write");
        assert_eq!(n, payload.len());
        let mut rbuf = [0u8; 32];
        let r = child.file_ops.read(&file, &mut rbuf, 0).expect("read");
        assert_eq!(r, payload.len());
        assert_eq!(&rbuf[..r], payload);
    }

    #[test]
    fn write_at_offset_extends() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        let child = root.ops.create(&root, b"f", 0o644).expect("create");
        let file = open_inode(&sb, child.clone());
        child.file_ops.write(&file, b"hello", 0).expect("write 0");
        child.file_ops.write(&file, b" world", 5).expect("write 5");
        let mut buf = [0u8; 20];
        let n = child.file_ops.read(&file, &mut buf, 0).expect("read");
        assert_eq!(&buf[..n], b"hello world");
    }

    #[test]
    fn nlink_accounting_nested_dirs() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.mkdir(&root, b"a", 0o755).expect("mkdir a");
        assert_eq!(root.meta.read().nlink, 3);
        let a = root.ops.lookup(&root, b"a").expect("a");
        a.ops.mkdir(&a, b"b", 0o755).expect("mkdir b");
        assert_eq!(a.meta.read().nlink, 3);
        a.ops.rmdir(&a, b"b").expect("rmdir b");
        assert_eq!(a.meta.read().nlink, 2);
    }

    #[test]
    fn hardlink_count() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.create(&root, b"f", 0o644).expect("create");
        let f = root.ops.lookup(&root, b"f").expect("f");
        root.ops.link(&root, b"f2", &f).expect("link f2");
        root.ops.link(&root, b"f3", &f).expect("link f3");
        assert_eq!(f.meta.read().nlink, 3);
        root.ops.unlink(&root, b"f").expect("unlink f");
        root.ops.unlink(&root, b"f2").expect("unlink f2");
        root.ops.unlink(&root, b"f3").expect("unlink f3");
        assert_eq!(f.meta.read().nlink, 0);
        assert!(f.state.lock().unlinked);
    }

    #[test]
    fn getdents_iteration() {
        let sb = make_ramfs();
        let root = root_of(&sb);
        root.ops.create(&root, b"alpha", 0o644).expect("alpha");
        root.ops.create(&root, b"beta", 0o644).expect("beta");
        let file = open_inode(&sb, root.clone());

        let mut all_names: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        let mut cookie = 0u64;
        let mut buf = [0u8; 256];
        loop {
            let n = root
                .file_ops
                .getdents(&file, &mut buf, &mut cookie)
                .expect("getdents");
            if n == 0 {
                break;
            }
            let mut pos = 0;
            while pos + 19 <= n {
                let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
                if reclen == 0 {
                    break;
                }
                let name_raw = &buf[pos + 19..pos + reclen];
                let nul = name_raw
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_raw.len());
                all_names.push(name_raw[..nul].to_vec());
                pos += reclen;
            }
        }

        assert!(all_names.iter().any(|n| n == b"."), "missing .");
        assert!(all_names.iter().any(|n| n == b".."), "missing ..");
        assert!(all_names.iter().any(|n| n == b"alpha"), "missing alpha");
        assert!(all_names.iter().any(|n| n == b"beta"), "missing beta");
    }

    #[test]
    fn statfs_returns_ramfs_magic() {
        let sb = make_ramfs();
        let fs = StatFs {
            ..Default::default()
        };
        let sf = sb.ops.statfs().expect("statfs");
        assert_eq!(sf.f_type, RAMFS_MAGIC);
        assert_eq!(sf.f_bsize, 4096);
    }
}
