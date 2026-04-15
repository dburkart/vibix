//! VFS-backed path syscalls: `open`, `openat`, `stat`, `fstat`, `lstat`,
//! `newfstatat`.
//!
//! Scope (RFC 0002 item 11/15, issue #238, read-path subset):
//!
//! - No `O_CREAT` — any `open` that would create returns `-EPERM` via
//!   the default `InodeOps::create` trait body. `open` on a non-existent
//!   path returns `-ENOENT`.
//! - No `chdir` / per-process cwd yet (tracked in #239) — relative paths
//!   resolve against the namespace root until that lands.
//! - Legacy compat: `/dev/stdin`, `/dev/stdout`, `/dev/stderr`,
//!   `/dev/serial` still short-circuit to [`SerialBackend`] so the
//!   boot-time init binary keeps working until a real `/dev/serial`
//!   character device is wired up.
//!
//! All handlers share:
//! - `copy_path_from_user` for bounded user-path copy-in.
//! - `resolve_inode` / `resolve_and_open` for path_walk + SB pinning.
//! - `write_stat` for the userspace `struct stat` copy-out.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::super::syscall::copy_path_from_user_pub;
use super::super::uaccess;
use crate::fs::vfs::dentry::{DFlags, Dentry};
use crate::fs::vfs::ops::{meta_into_stat, Stat};
use crate::fs::vfs::ops::{SetAttr, SetAttrMask};
use crate::fs::vfs::path_walk::{path_walk, LookupFlags, MountResolver, NameIdata, PATH_MAX};
use crate::fs::vfs::super_block::SbActiveGuard;
use crate::fs::vfs::Credential;
use crate::fs::vfs::{
    root as vfs_root, GlobalMountResolver, Inode, InodeKind, OpenFile, VfsBackend,
};
use crate::fs::{
    flags as oflags, FileBackend, FileDescription, EBADF, EEXIST, EINVAL, EISDIR, ENAMETOOLONG,
    ENOENT, ENOMEM, ENOTDIR,
};

/// Linux x86_64 value of the "use the current working directory"
/// sentinel for `*at` syscalls. Sign-extended as an `i32`, negative,
/// so it never collides with a live fd number.
pub const AT_FDCWD: i32 = -100;

/// `AT_SYMLINK_NOFOLLOW` — the `*at` flag that asks the resolver to
/// stop on a trailing symlink rather than following it.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

/// `AT_EMPTY_PATH` — treat an empty `path` as a reference to the file
/// behind `dfd` (used by `fstatat(fd, "", &st, AT_EMPTY_PATH)`).
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Copy a user path into a heap buffer sized at `PATH_MAX + 1`. The
/// `+1` lets `copy_path_from_user_pub` observe the terminating NUL
/// within the buffer for paths of exactly `PATH_MAX` user bytes;
/// anything longer returns `-ENAMETOOLONG`. A heap buffer avoids a
/// 4 KiB stack frame on every VFS syscall.
///
/// Uses fallible allocation (`try_reserve_exact`) so a heap-pressure
/// situation surfaces as `-ENOMEM` to userspace instead of tripping
/// the kernel-wide `panic = "abort"` handler — a user syscall must
/// never be a DoS vector against the kernel.
fn copy_user_path(path_uva: u64) -> Result<Vec<u8>, i64> {
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(PATH_MAX + 1).map_err(|_| ENOMEM)?;
    buf.resize(PATH_MAX + 1, 0u8);
    let n = unsafe { copy_path_from_user_pub(path_uva as usize, &mut buf) }?;
    buf.truncate(n);
    Ok(buf)
}

/// Resolve a user path to an `Arc<Inode>` via `path_walk`.
///
/// `follow` controls whether a terminal symlink is followed
/// (`stat` vs `lstat`). Returns `(inode, sb_guard_holder)` on success —
/// the holder is an `Arc<SbActiveGuard>`-equivalent: we return the
/// `NameIdata`'s `edges` vector so the caller's `Arc<SuperBlock>`
/// references keep the SB alive for the duration of the `getattr` call.
fn resolve_inode(path: &[u8], follow: bool) -> Result<(Arc<Inode>, NameIdata), i64> {
    let root = vfs_root().ok_or(ENOENT)?;
    // For relative paths, walk from the per-process cwd. For absolute
    // paths, path_walk reseats at root on the first `/` component so
    // the cwd argument is ignored — but we still pass root as cwd for
    // absolute paths since that is the correct sentinel.
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
    Ok((inode, nd))
}

/// Fill `out` from `inode.ops.getattr`, then copy out to user.
fn stat_into_user(inode: &Arc<Inode>, user_statbuf: u64) -> i64 {
    if user_statbuf == 0 {
        return EINVAL;
    }
    if let Err(e) = uaccess::check_user_range(user_statbuf as usize, core::mem::size_of::<Stat>()) {
        return e.as_errno();
    }
    // Zero-init to avoid padding infoleak (Sec-B4 per RFC 0002).
    let mut st = Stat::default();
    if let Err(e) = inode.ops.getattr(inode, &mut st) {
        return e;
    }
    // Drivers that don't fill fs_id/ino should get sane defaults from
    // `meta_into_stat` — but any driver implementing its own getattr is
    // expected to set them. We re-apply from the inode as a safety net
    // so a stubbed getattr that returned Ok without touching `out`
    // still emits a coherent stat.
    if st.st_ino == 0 {
        let meta = inode.meta.read();
        let fs_id = inode.sb.upgrade().map(|s| s.fs_id.0).unwrap_or(0);
        meta_into_stat(&meta, inode.kind, fs_id, inode.ino, &mut st);
    }
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &st as *const Stat as *const u8,
            core::mem::size_of::<Stat>(),
        )
    };
    match unsafe { uaccess::copy_to_user(user_statbuf as usize, bytes) } {
        Ok(()) => 0,
        Err(e) => e.as_errno(),
    }
}

/// Install `backend` into the current fd table. `flags` contains the
/// caller's `O_*` flags; access-mode bits go into `FileDescription.flags`
/// and `O_CLOEXEC` is split into the per-fd slot via `alloc_fd_with_flags`.
fn install_fd(backend: Arc<dyn FileBackend>, flags: u32) -> i64 {
    // Preserve every status flag the caller passed (access mode, O_APPEND,
    // O_NONBLOCK, etc.) on the open-file description so fcntl(F_GETFL)
    // returns the full set. The per-fd O_CLOEXEC bit is split out into the
    // slot's fd_flags — dup'd fds must not inherit it.
    let fd_flags = flags & oflags::O_CLOEXEC;
    // Only POSIX file-status flags persist on the open-file description.
    // Creation-time / path-resolution bits (O_CREAT, O_EXCL, O_TRUNC,
    // O_DIRECTORY, O_NOFOLLOW) affect open() only and must not surface
    // via fcntl(F_GETFL).
    let status_flags =
        flags & (oflags::O_ACCMODE | oflags::O_APPEND | oflags::O_NONBLOCK | oflags::O_ASYNC);
    let desc = Arc::new(FileDescription::new(backend, status_flags));
    let tbl = crate::task::current_fd_table();
    let result = tbl.lock().alloc_fd_with_flags(desc, fd_flags);
    match result {
        Ok(fd) => fd as i64,
        Err(e) => e,
    }
}

/// Split `path` into its parent directory and final component for
/// `O_CREAT`-style dispatch. Rejects inputs with no nameable leaf — an
/// empty path, a bare `/`, or anything whose final component is `.` /
/// `..` / empty (trailing slash) — since `create(parent, leaf)` cannot
/// act on them.
fn split_parent(path: &[u8]) -> Result<(&[u8], &[u8]), i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    // Strip a trailing slash for "/foo/" but keep bare "/" as-is so the
    // rejection below triggers.
    let trimmed = if path.len() > 1 && *path.last().unwrap() == b'/' {
        &path[..path.len() - 1]
    } else {
        path
    };
    let (parent, leaf) = match trimmed.iter().rposition(|&b| b == b'/') {
        Some(0) => (&b"/"[..], &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (&b"."[..], trimmed),
    };
    if leaf.is_empty() || leaf == b"." || leaf == b".." {
        return Err(ENOENT);
    }
    Ok((parent, leaf))
}

/// `/dev/{stdin,stdout,stderr,serial}` legacy compat: returns a
/// `SerialBackend`-backed description when path matches. None otherwise.
fn legacy_dev_backend(path: &[u8], flags: u64) -> Option<i64> {
    let is_special = matches!(
        path,
        b"/dev/stdin" | b"/dev/stdout" | b"/dev/stderr" | b"/dev/serial"
    );
    if !is_special {
        return None;
    }
    let safe_flags =
        (flags as u32) & (oflags::O_RDONLY | oflags::O_WRONLY | oflags::O_RDWR | oflags::O_CLOEXEC);
    let backend: Arc<dyn FileBackend> = Arc::new(crate::fs::SerialBackend::new());
    Some(install_fd(backend, safe_flags))
}

/// Shared `open` body: used by `sys_open` (dfd == AT_FDCWD) and
/// `sys_openat`.
///
/// `dfd` is accepted but only `AT_FDCWD` is honored today — passing a
/// real fd for a relative path returns `-EINVAL` because per-process
/// cwd / fd-rooted walks don't exist yet (#239).
pub unsafe fn sys_openat_impl(dfd: i32, path_uva: u64, flags: u64, mode: u64) -> i64 {
    // 1. Copy the user path.
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();
    let flags32 = flags as u32;

    // 2. Legacy /dev/{stdin,stdout,stderr,serial} fast path. Bypasses
    //    the VFS so a smoke boot that opens these before the devfs
    //    character devices exist keeps working.
    if let Some(r) = legacy_dev_backend(path, flags) {
        return r;
    }

    // 3. `*at` preconditions. Non-AT_FDCWD dfd is out of scope for the
    //    read-path subset; absolute paths ignore dfd entirely.
    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    // 4. Walk. If O_CREAT is set and the leaf does not exist, try to
    //    create it in the parent directory, then re-walk.
    let follow = flags32 & oflags::O_NOFOLLOW == 0;
    let (inode, nd) = match resolve_inode(path, follow) {
        Ok(v) => {
            // File exists. With O_CREAT|O_EXCL this is an error.
            if flags32 & oflags::O_CREAT != 0 && flags32 & oflags::O_EXCL != 0 {
                return EEXIST;
            }
            v
        }
        Err(e) if e == ENOENT && flags32 & oflags::O_CREAT != 0 => {
            let (parent_path, leaf) = match split_parent(path) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let (parent_inode, _pnd) = match resolve_inode(parent_path, /* follow */ true) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if parent_inode.kind != InodeKind::Dir {
                return ENOTDIR;
            }
            let create_mode = (mode as u16) & 0o7777;
            if let Err(e) = parent_inode.ops.create(&parent_inode, leaf, create_mode) {
                return e;
            }
            // Re-resolve to pick up the freshly created dentry+inode.
            match resolve_inode(path, follow) {
                Ok(v) => v,
                Err(e) => return e,
            }
        }
        Err(e) => return e,
    };

    // 5. O_DIRECTORY check.
    if flags32 & oflags::O_DIRECTORY != 0 && inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // 6. O_TRUNC: zero the file length for a writable open on a regular
    //    file. Silently ignored on a read-only open (Linux semantics);
    //    rejected with EISDIR on a directory.
    if flags32 & oflags::O_TRUNC != 0 {
        if inode.kind == InodeKind::Dir {
            return EISDIR;
        }
        let access = flags32 & oflags::O_ACCMODE;
        if inode.kind == InodeKind::Reg && (access == oflags::O_WRONLY || access == oflags::O_RDWR)
        {
            let attr = SetAttr {
                mask: SetAttrMask::SIZE,
                size: 0,
                ..SetAttr::default()
            };
            if let Err(e) = inode.ops.setattr(&inode, &attr) {
                return e;
            }
        }
    }

    // 7. Build the OpenFile. The edge list in `nd` keeps the SB alive
    //    until we've successfully acquired our own `SbActiveGuard`.
    let sb = match inode.sb.upgrade() {
        Some(s) => s,
        None => return ENOENT,
    };
    let guard = match SbActiveGuard::try_acquire(&sb) {
        Ok(g) => g,
        Err(e) => return e,
    };
    // `OpenFile::new` takes `sb: Arc<SuperBlock>` by value and
    // `guard: SbActiveGuard<'_>` also by value. Cloning the `Arc` for
    // the `sb` argument keeps `sb` live for the `guard`'s lifetime.
    let sb_for_of = sb.clone();
    let of = OpenFile::new(
        nd.path.dentry.clone(),
        inode.clone(),
        inode.file_ops.clone(),
        sb_for_of,
        flags as u32,
        guard,
    );
    let backend: Arc<dyn FileBackend> = Arc::new(VfsBackend { open_file: of });
    install_fd(backend, flags as u32)
}

/// `stat(path, *statbuf)` (follow=true) / `lstat(path, *statbuf)`
/// (follow=false — `nofollow=true` here flips the sense).
pub unsafe fn sys_stat_impl(path_uva: u64, statbuf_uva: u64, nofollow: bool) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let (inode, _nd) = match resolve_inode(path, !nofollow) {
        Ok(v) => v,
        Err(e) => return e,
    };
    stat_into_user(&inode, statbuf_uva)
}

/// `fstat(fd, *statbuf)` — read `struct stat` of the file behind an
/// already-open fd.
pub unsafe fn sys_fstat_impl(fd_raw: u64, statbuf_uva: u64) -> i64 {
    // Linux fd space fits in u32; values above that are always invalid.
    if fd_raw > u32::MAX as u64 {
        return EBADF;
    }
    let fd = fd_raw as u32;
    let tbl = crate::task::current_fd_table();
    let backend = match tbl.lock().get(fd) {
        Ok(b) => b,
        Err(_) => return EBADF,
    };
    // Non-VFS backends (SerialBackend on fds 0/1/2 before execve) have
    // no Inode; fstat on them yields -EINVAL per POSIX for "no such
    // attribute". This matches Linux's `generic_file_fstat` on a
    // pipe/socket fd whose inode lookup returns nothing useful.
    let vfs = match backend.as_vfs() {
        Some(v) => v,
        None => return EINVAL,
    };
    stat_into_user(&vfs.open_file.inode, statbuf_uva)
}

/// `newfstatat(dfd, path, *statbuf, flags)` — the `*at` form of stat.
///
/// Supports `AT_SYMLINK_NOFOLLOW` and `AT_EMPTY_PATH`. Rejects any
/// other flag bit with `-EINVAL` so future additions (`AT_NO_AUTOMOUNT`
/// etc.) have to be whitelisted explicitly.
pub unsafe fn sys_newfstatat_impl(dfd: i32, path_uva: u64, statbuf_uva: u64, flags: u32) -> i64 {
    let known = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if flags & !known != 0 {
        return EINVAL;
    }

    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    // AT_EMPTY_PATH + empty path + real fd: stat the file behind dfd.
    // AT_FDCWD (-100) is not a valid fd for this purpose — reject it
    // until per-process cwd semantics land (#239).
    if flags & AT_EMPTY_PATH != 0 && path.is_empty() {
        if dfd == AT_FDCWD {
            return EINVAL;
        }
        return sys_fstat_impl(dfd as u64, statbuf_uva);
    }

    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (inode, _nd) = match resolve_inode(path, follow) {
        Ok(v) => v,
        Err(e) => return e,
    };
    stat_into_user(&inode, statbuf_uva)
}

/// `chdir(path)` — set the per-process current working directory.
///
/// Resolves `path` (following symlinks), checks the target is a
/// directory, then stores its dentry as the task's cwd via
/// [`crate::task::set_current_cwd`].
pub unsafe fn sys_chdir(path_uva: u64) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let (inode, nd) = match resolve_inode(path, /* follow */ true) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    crate::task::set_current_cwd(nd.path.dentry.clone());
    0
}

/// `getcwd(buf, len)` — copy the absolute path of the current working
/// directory into the user buffer.
///
/// Walks the dentry parent chain from the cwd (or VFS root if no cwd
/// is set) up to the root, collecting component names, then assembles
/// and copies out `"/component/…\0"`.
///
/// Returns the number of bytes written (including the terminating NUL)
/// on success, or a negative errno:
/// - `-ENOENT` if the VFS root is not yet initialised.
/// - `-EINVAL` if `buf` is NULL or `len` is 0.
/// - `-ENAMETOOLONG` if the path does not fit in `len` bytes.
/// - `-EFAULT` if `buf` is not a valid user-space range.
pub unsafe fn sys_getcwd(buf_uva: u64, len: u64) -> i64 {
    if buf_uva == 0 || len == 0 {
        return EINVAL;
    }
    let len = len as usize;

    // Resolve the cwd: fall back to VFS root.
    let cwd = match crate::task::current_cwd().or_else(vfs_root) {
        Some(d) => d,
        None => return ENOENT,
    };

    // Walk the parent chain. We hold strong Arcs in `chain` to keep
    // dentries alive while assembling the path string.
    //
    // Mount crossings: when we land on an `IS_ROOT` dentry, query
    // `MOUNT_TABLE` for the edge whose `root_dentry` is this dentry. If
    // found, the mountpoint in the parent FS is the next step upward and
    // its name is what belongs in the path. If not found (we are at the
    // VFS namespace root), stop.
    let mut chain: Vec<Arc<Dentry>> = Vec::new();
    let resolver = GlobalMountResolver;

    let mut cur = cwd.clone();
    loop {
        if cur.flags.contains(DFlags::IS_ROOT) {
            // Check if this is a mounted root (has a parent FS above it).
            match resolver.mount_above(&cur) {
                Some(edge) => {
                    // Cross back up to the mountpoint in the parent FS.
                    // The mountpoint's name is the directory name in the
                    // parent (e.g. "dev" for /dev).
                    match edge.mountpoint.upgrade() {
                        Some(mp) => {
                            chain.push(mp.clone());
                            match mp.parent.upgrade() {
                                Some(parent) => cur = parent,
                                None => break,
                            }
                        }
                        None => break, // mountpoint dropped — treat as root
                    }
                }
                None => break, // namespace root — stop
            }
        } else {
            chain.push(cur.clone());
            match cur.parent.upgrade() {
                Some(parent) => cur = parent,
                None => break,
            }
        }
    }

    // Build "/comp1/comp2/…\0".
    // Total length: 1 ('/') + sum(name_len + 1 per component) + 1 (NUL).
    // For root cwd the chain is empty → path is "/\0".
    let mut path_len = 1usize; // leading '/'
    for d in chain.iter().rev() {
        path_len += d.name.as_bytes().len() + 1; // '/' + name
    }
    path_len += 1; // NUL

    if path_len > len {
        return ENAMETOOLONG;
    }

    if let Err(e) = uaccess::check_user_range(buf_uva as usize, path_len) {
        return e.as_errno();
    }

    // Assemble into a kernel buffer.
    let mut out: Vec<u8> = Vec::with_capacity(path_len);
    // If cwd is root, chain is empty.
    if chain.is_empty() {
        out.push(b'/');
    } else {
        for d in chain.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(d.name.as_bytes());
        }
    }
    out.push(0); // NUL terminator

    match uaccess::copy_to_user(buf_uva as usize, &out) {
        Ok(()) => out.len() as i64,
        Err(e) => e.as_errno(),
    }
}
