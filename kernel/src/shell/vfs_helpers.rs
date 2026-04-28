//! Kernel-context VFS helpers used by the shell's file-touching builtins.
//!
//! The userspace `sys_*` arms in [`crate::arch::x86_64::syscalls::vfs`]
//! deal in user pointers, fd tables, and per-task credentials; the
//! shell already runs in the kernel as a privileged task and just
//! needs simple "given a path string, do X" entry points. Putting them
//! here keeps the dispatch in [`super`] surgical and avoids reinventing
//! the path-walk wheel inside every builtin.
//!
//! Every helper resolves relative paths against [`crate::task::current_cwd`]
//! (the shell task's CWD, mutable via `cd`) and uses
//! [`super::super::fs::vfs::Credential::kernel`] for permission checks —
//! the kernel-resident shell is root by construction.
//!
//! The integration test harness drives these helpers directly. They
//! never panic on error; failures are surfaced as `i64` errnos so the
//! caller can render a useful message.

#![cfg(target_os = "none")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::vfs::dentry::Dentry;
use crate::fs::vfs::inode::Inode;
use crate::fs::vfs::open_file::OpenFile;
use crate::fs::vfs::ops::Stat;
use crate::fs::vfs::path_walk::{path_walk, LookupFlags, NameIdata};
use crate::fs::vfs::super_block::SbActiveGuard;
use crate::fs::vfs::{root as vfs_root, Credential, GlobalMountResolver, InodeKind};
use crate::fs::{ENOENT, ENOTDIR};

/// Path resolution result: the resolved inode plus a `NameIdata` whose
/// `edges` field keeps the traversed mounts pinned for as long as the
/// caller holds the result.
pub struct Resolved {
    pub inode: Arc<Inode>,
    pub dentry: Arc<Dentry>,
    pub _nd: NameIdata,
}

/// Walk `path` from the shell's CWD (or root for absolute paths) using
/// the kernel root credential.
pub fn resolve(path: &[u8], follow: bool) -> Result<Resolved, i64> {
    let root = vfs_root().ok_or(ENOENT)?;
    let cwd = if path.first() == Some(&b'/') {
        root.clone()
    } else {
        crate::task::current_cwd().unwrap_or_else(|| root.clone())
    };
    let mut flags = LookupFlags::default();
    if follow {
        flags = flags | LookupFlags::FOLLOW;
    } else {
        flags = flags | LookupFlags::NOFOLLOW;
    }
    let mut nd = NameIdata::new(root, cwd, Credential::kernel(), flags)?;
    path_walk(&mut nd, path, &GlobalMountResolver)?;
    let inode = nd.path.inode.clone();
    let dentry = nd.path.dentry.clone();
    Ok(Resolved {
        inode,
        dentry,
        _nd: nd,
    })
}

/// Resolve the parent directory of `path`, returning `(parent_inode,
/// parent_dentry, leaf_bytes)`. Rejects empty / `/` / `.` / `..`
/// trailing-component inputs with `ENOENT`.
pub fn split_and_resolve_parent(path: &[u8]) -> Result<(Arc<Inode>, Arc<Dentry>, Vec<u8>), i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    let trimmed: &[u8] = if path.len() > 1 && *path.last().unwrap() == b'/' {
        &path[..path.len() - 1]
    } else {
        path
    };
    let (parent_path, leaf) = match trimmed.iter().rposition(|&b| b == b'/') {
        Some(0) => (&b"/"[..], &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (&b"."[..], trimmed),
    };
    if leaf.is_empty() || leaf == b"." || leaf == b".." {
        return Err(ENOENT);
    }
    let parent = resolve(parent_path, /* follow */ true)?;
    if parent.inode.kind != InodeKind::Dir {
        return Err(ENOTDIR);
    }
    Ok((parent.inode, parent.dentry, leaf.to_vec()))
}

/// Build an `OpenFile` for the resolved inode. Used for read/write/
/// getdents loops in the builtins.
pub fn open_inode(inode: &Arc<Inode>, dentry: &Arc<Dentry>) -> Result<Arc<OpenFile>, i64> {
    let sb = inode.sb.upgrade().ok_or(ENOENT)?;
    let guard = SbActiveGuard::try_acquire(&sb)?;
    let sb_for_of = sb.clone();
    let of = OpenFile::new(
        dentry.clone(),
        inode.clone(),
        inode.file_ops.clone(),
        sb_for_of,
        0,
        guard,
    );
    Ok(of)
}

/// Read the entire contents of a regular file at `path` into a
/// heap-allocated buffer.
pub fn read_all(path: &[u8]) -> Result<Vec<u8>, i64> {
    let r = resolve(path, /* follow */ true)?;
    if r.inode.kind == InodeKind::Dir {
        return Err(crate::fs::EISDIR);
    }
    let of = open_inode(&r.inode, &r.dentry)?;
    let mut out = Vec::new();
    let mut off: u64 = 0;
    let mut chunk = [0u8; 512];
    loop {
        let n = match r.inode.file_ops.read(&of, &mut chunk, off) {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        off += n as u64;
        if n < chunk.len() {
            // Some FOps return a short read at EOF without a follow-up
            // zero. Probe once more to catch the genuine zero so we
            // don't loop forever on a saturated buffer.
        }
    }
    Ok(out)
}

/// Write `data` to a freshly-truncated file at `path`. Creates the file
/// if it does not exist (mode 0o644).
pub fn write_all(path: &[u8], data: &[u8]) -> Result<(), i64> {
    // Try to resolve first; if missing, create.
    let r = match resolve(path, /* follow */ true) {
        Ok(r) => r,
        Err(e) if e == ENOENT => {
            create_file(path, 0o644)?;
            resolve(path, true)?
        }
        Err(e) => return Err(e),
    };
    if r.inode.kind == InodeKind::Dir {
        return Err(crate::fs::EISDIR);
    }
    // Truncate before write.
    let attr = crate::fs::vfs::ops::SetAttr {
        mask: crate::fs::vfs::ops::SetAttrMask::SIZE,
        size: 0,
        ..crate::fs::vfs::ops::SetAttr::default()
    };
    r.inode.ops.setattr(&r.inode, &attr)?;
    let of = open_inode(&r.inode, &r.dentry)?;
    let mut off: u64 = 0;
    while off < data.len() as u64 {
        let n = r.inode.file_ops.write(&of, &data[off as usize..], off)?;
        if n == 0 {
            return Err(crate::fs::EIO);
        }
        off += n as u64;
    }
    Ok(())
}

/// Create a regular file (no overwrite). Returns `EEXIST` if it
/// already exists.
pub fn create_file(path: &[u8], mode: u16) -> Result<(), i64> {
    let (parent_inode, _parent_dentry, leaf) = split_and_resolve_parent(path)?;
    parent_inode
        .ops
        .create(&parent_inode, &leaf, mode & 0o7777)?;
    Ok(())
}

/// `mkdir` a directory at `path`. No `-p`.
pub fn mkdir(path: &[u8], mode: u16) -> Result<(), i64> {
    let (parent_inode, _, leaf) = split_and_resolve_parent(path)?;
    parent_inode
        .ops
        .mkdir(&parent_inode, &leaf, mode & 0o7777)?;
    Ok(())
}

/// Unlink a file (regular file or symlink) at `path`.
pub fn unlink(path: &[u8]) -> Result<(), i64> {
    let (parent_inode, _, leaf) = split_and_resolve_parent(path)?;
    parent_inode.ops.unlink(&parent_inode, &leaf)
}

/// Remove an empty directory at `path`.
pub fn rmdir(path: &[u8]) -> Result<(), i64> {
    let (parent_inode, _, leaf) = split_and_resolve_parent(path)?;
    parent_inode.ops.rmdir(&parent_inode, &leaf)
}

/// Hardlink `target` to `link_path`.
pub fn link(target_path: &[u8], link_path: &[u8]) -> Result<(), i64> {
    let target = resolve(target_path, /* follow */ false)?;
    if target.inode.kind == InodeKind::Dir {
        // POSIX forbids hardlinking directories.
        return Err(crate::fs::EPERM);
    }
    let (parent_inode, _, leaf) = split_and_resolve_parent(link_path)?;
    parent_inode.ops.link(&parent_inode, &leaf, &target.inode)
}

/// Stream the contents of `src_path` to `dst_path` without ever
/// holding the whole file in memory. Truncates / creates the
/// destination, then reads `src` in fixed-size chunks and writes each
/// chunk straight to `dst`. Caps the total bytes copied at
/// `max_bytes` and returns `EFBIG` if the source exceeds that — this
/// is the kernel-shell guardrail against `cp /dev/zero …` taking the
/// box down.
pub fn stream_copy(src_path: &[u8], dst_path: &[u8], max_bytes: u64) -> Result<u64, i64> {
    let src = resolve(src_path, /* follow */ true)?;
    if src.inode.kind == InodeKind::Dir {
        return Err(crate::fs::EISDIR);
    }
    // Resolve-or-create the destination.
    let dst = match resolve(dst_path, /* follow */ true) {
        Ok(r) => r,
        Err(e) if e == ENOENT => {
            create_file(dst_path, 0o644)?;
            resolve(dst_path, /* follow */ true)?
        }
        Err(e) => return Err(e),
    };
    if dst.inode.kind == InodeKind::Dir {
        return Err(crate::fs::EISDIR);
    }
    // Truncate destination.
    let attr = crate::fs::vfs::ops::SetAttr {
        mask: crate::fs::vfs::ops::SetAttrMask::SIZE,
        size: 0,
        ..crate::fs::vfs::ops::SetAttr::default()
    };
    dst.inode.ops.setattr(&dst.inode, &attr)?;

    let src_of = open_inode(&src.inode, &src.dentry)?;
    let dst_of = open_inode(&dst.inode, &dst.dentry)?;

    let mut buf = [0u8; 4096];
    let mut copied: u64 = 0;
    let mut roff: u64 = 0;
    let mut woff: u64 = 0;
    loop {
        let remaining = max_bytes.saturating_sub(copied);
        if remaining == 0 {
            return Err(crate::fs::EFBIG);
        }
        let take = core::cmp::min(remaining as usize, buf.len());
        let n = src.inode.file_ops.read(&src_of, &mut buf[..take], roff)?;
        if n == 0 {
            break;
        }
        roff += n as u64;
        let mut written = 0usize;
        while written < n {
            let w = dst.inode.file_ops.write(&dst_of, &buf[written..n], woff)?;
            if w == 0 {
                return Err(crate::fs::EIO);
            }
            woff += w as u64;
            written += w;
        }
        copied += n as u64;
    }
    Ok(copied)
}

/// Rename `old_path` to `new_path`. Tries `InodeOps::rename` first;
/// if the driver returns `EPERM` (no rename support) the caller can
/// fall back to `link` + `unlink`.
pub fn rename(old_path: &[u8], new_path: &[u8]) -> Result<(), i64> {
    let (old_parent, _, old_leaf) = split_and_resolve_parent(old_path)?;
    let (new_parent, _, new_leaf) = split_and_resolve_parent(new_path)?;
    old_parent
        .ops
        .rename(&old_parent, &old_leaf, &new_parent, &new_leaf)
}

/// `getattr` for `stat`. Follows trailing symlinks.
pub fn stat(path: &[u8]) -> Result<(Stat, InodeKind), i64> {
    let r = resolve(path, /* follow */ true)?;
    let mut st = Stat::default();
    r.inode.ops.getattr(&r.inode, &mut st)?;
    if st.st_ino == 0 {
        let meta = r.inode.meta.read();
        let fs_id = r.inode.sb.upgrade().map(|s| s.fs_id.0).unwrap_or(0);
        crate::fs::vfs::ops::meta_into_stat(&meta, r.inode.kind, fs_id, r.inode.ino, &mut st);
    }
    Ok((st, r.inode.kind))
}

/// Compute the absolute path of `dentry` by walking parent pointers.
/// Returns "/" for the root dentry. Used by `pwd` / `getcwd`.
///
/// Mount roots: each mounted filesystem's root dentry is self-parenting
/// and named `.`, so a naive walk would terminate at the wrong place
/// and produce names like `/.` for `/tmp`. We detect a mount-root by
/// flag (`DFlags::IS_ROOT`) and consult [`GlobalMountResolver`] to jump
/// up to the parent-side mountpoint dentry instead. The mountpoint
/// dentry's name is the user-visible component (e.g. `tmp`).
pub fn dentry_path(dentry: &Arc<Dentry>) -> String {
    use crate::fs::vfs::dentry::DFlags;
    use crate::fs::vfs::path_walk::MountResolver;
    let root = match vfs_root() {
        Some(r) => r,
        None => return String::from("/"),
    };
    if Arc::ptr_eq(dentry, &root) {
        return String::from("/");
    }
    let mounts = GlobalMountResolver;
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut cur = dentry.clone();
    let mut hops = 0;
    while !Arc::ptr_eq(&cur, &root) && hops < 256 {
        // Cross up through any mount edges first: the top-of-mount
        // dentry has the placeholder name `.`; its mountpoint on the
        // parent FS carries the user-visible name.
        if cur.flags.contains(DFlags::IS_ROOT) {
            if let Some(edge) = mounts.mount_above(&cur) {
                if let Some(mp) = edge.mountpoint.upgrade() {
                    cur = mp;
                    continue;
                }
            }
            // No mount edge to cross: bail out at the namespace root
            // (the only IS_ROOT dentry without a mount above).
            break;
        }
        parts.push(cur.name.as_bytes().to_vec());
        let parent = match cur.parent.upgrade() {
            Some(p) => p,
            None => break,
        };
        if Arc::ptr_eq(&parent, &cur) {
            // self-parent: we hit the namespace root via the
            // self-cycle convention. Stop.
            break;
        }
        cur = parent;
        hops += 1;
    }
    let mut out = String::new();
    for chunk in parts.iter().rev() {
        out.push('/');
        match core::str::from_utf8(chunk) {
            Ok(s) => out.push_str(s),
            Err(_) => out.push_str("?"),
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Iterate directory entries via `getdents`. Calls `cb(name, kind)` for
/// each entry, including `.` and `..`. `cb` returning `false` stops
/// iteration early.
pub fn for_each_dirent<F: FnMut(&[u8], u8) -> bool>(
    inode: &Arc<Inode>,
    dentry: &Arc<Dentry>,
    mut cb: F,
) -> Result<(), i64> {
    if inode.kind != InodeKind::Dir {
        return Err(ENOTDIR);
    }
    let of = open_inode(inode, dentry)?;
    let mut cookie: u64 = 0;
    let mut buf = [0u8; 1024];
    loop {
        let n = inode.file_ops.getdents(&of, &mut buf, &mut cookie)?;
        if n == 0 {
            break;
        }
        let mut off = 0usize;
        while off + 19 <= n {
            // linux_dirent64 header layout — see `emit_dirent` in
            // ramfs.rs for the canonical writer.
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > n {
                break;
            }
            let d_type = buf[off + 18];
            // Name runs from off+19 to the first NUL within the record.
            let name_start = off + 19;
            let name_end_max = off + reclen;
            let mut name_end = name_start;
            while name_end < name_end_max && buf[name_end] != 0 {
                name_end += 1;
            }
            let name = &buf[name_start..name_end];
            if !cb(name, d_type) {
                return Ok(());
            }
            off += reclen;
        }
    }
    Ok(())
}
