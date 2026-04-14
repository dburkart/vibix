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
use alloc::vec;
use alloc::vec::Vec;

use super::super::syscall::copy_path_from_user_pub;
use super::super::uaccess;
use crate::fs::vfs::ops::{meta_into_stat, Stat};
use crate::fs::vfs::path_walk::{path_walk, LookupFlags, NameIdata, PATH_MAX};
use crate::fs::vfs::super_block::SbActiveGuard;
use crate::fs::vfs::Credential;
use crate::fs::vfs::{
    root as vfs_root, GlobalMountResolver, Inode, InodeKind, OpenFile, VfsBackend,
};
use crate::fs::{flags as oflags, FileBackend, FileDescription, EBADF, EINVAL, ENOENT, ENOTDIR};

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
fn copy_user_path(path_uva: u64) -> Result<Vec<u8>, i64> {
    let mut buf: Vec<u8> = vec![0u8; PATH_MAX + 1];
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
    let mut flags = LookupFlags::default();
    if follow {
        flags = flags | LookupFlags::FOLLOW;
    } else {
        flags = flags | LookupFlags::NOFOLLOW;
    }
    let mut nd = NameIdata::new(root.clone(), root, Credential::kernel(), flags)?;
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
    let access_flags = flags & (oflags::O_RDONLY | oflags::O_WRONLY | oflags::O_RDWR);
    let fd_flags = flags & oflags::O_CLOEXEC;
    let desc = Arc::new(FileDescription {
        backend,
        flags: access_flags,
    });
    let tbl = crate::task::current_fd_table();
    let result = tbl.lock().alloc_fd_with_flags(desc, fd_flags);
    match result {
        Ok(fd) => fd as i64,
        Err(e) => e,
    }
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
    let backend: Arc<dyn FileBackend> = Arc::new(crate::fs::SerialBackend);
    Some(install_fd(backend, safe_flags))
}

/// Shared `open` body: used by `sys_open` (dfd == AT_FDCWD) and
/// `sys_openat`.
///
/// `dfd` is accepted but only `AT_FDCWD` is honored today — passing a
/// real fd for a relative path returns `-EINVAL` because per-process
/// cwd / fd-rooted walks don't exist yet (#239).
pub unsafe fn sys_openat_impl(dfd: i32, path_uva: u64, flags: u64, _mode: u64) -> i64 {
    // 1. Copy the user path.
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    // 2. Mutating create/truncate flags not supported in the read-path
    //    subset. Fail loudly so userspace gets a clear signal rather than
    //    a silent no-op.
    let flags32 = flags as u32;
    if flags32 & oflags::O_CREAT != 0 {
        return crate::fs::EACCES;
    }
    if flags32 & oflags::O_TRUNC != 0 {
        return crate::fs::EACCES;
    }

    // 3. Legacy /dev/{stdin,stdout,stderr,serial} fast path. Bypasses
    //    the VFS so a smoke boot that opens these before the devfs
    //    character devices exist keeps working.
    if let Some(r) = legacy_dev_backend(path, flags) {
        return r;
    }

    // 4. `*at` preconditions. Non-AT_FDCWD dfd is out of scope for the
    //    read-path subset; absolute paths ignore dfd entirely.
    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    // 5. Walk.
    let follow = (flags as u32) & oflags::O_NOFOLLOW == 0;
    let (inode, nd) = match resolve_inode(path, follow) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // 6. O_DIRECTORY check.
    if (flags as u32) & oflags::O_DIRECTORY != 0 && inode.kind != InodeKind::Dir {
        return ENOTDIR;
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
    let fd_flags =
        (flags as u32) & (oflags::O_RDONLY | oflags::O_WRONLY | oflags::O_RDWR | oflags::O_CLOEXEC);
    install_fd(backend, fd_flags)
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
