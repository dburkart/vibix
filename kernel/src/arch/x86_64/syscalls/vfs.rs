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
use crate::fs::vfs::{
    root as vfs_root, GlobalMountResolver, Inode, InodeKind, OpenFile, VfsBackend,
};
use crate::fs::vfs::{Access, Credential};
use crate::fs::{
    flags as oflags, FileBackend, FileDescription, EBADF, EBUSY, EEXIST, EINVAL, EISDIR,
    ENAMETOOLONG, ENOENT, ENOMEM, ENOTDIR, EPERM,
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

/// `AT_REMOVEDIR` — flag to `unlinkat(2)` that dispatches to `rmdir`
/// semantics instead of `unlink`. Mirrors Linux's value.
pub const AT_REMOVEDIR: u32 = 0x200;

/// `S_ISVTX` — the POSIX "sticky bit" in `InodeMeta.mode`. When set on
/// a directory, `unlink`/`rename` require the caller to own either the
/// target file or the directory (or be root). Linux value 0o1000.
const S_ISVTX: u16 = 0o1000;

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
    resolve_inode_as(path, follow, Credential::kernel())
}

/// Like [`resolve_inode`] but walks the path using `cred` for
/// every intermediate `may_lookup` (search-permission) check.
///
/// Syscalls that make DAC decisions about the resolved inode —
/// `chmod`/`chown` and friends — pass the caller's per-task credential
/// here so that a non-root caller is rejected with `-EACCES` on an
/// unsearchable ancestor, instead of silently resolving as root and
/// then failing the subsequent ownership check with a misleading
/// errno. Read-only syscalls (`stat`/`open`) keep using the root
/// placeholder until Workstream B plumbs per-task credentials through
/// every call site in one go.
fn resolve_inode_as(
    path: &[u8],
    follow: bool,
    cred: Credential,
) -> Result<(Arc<Inode>, NameIdata), i64> {
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
    let mut nd = NameIdata::new(root, cwd, cred, flags)?;
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
    let rc = install_fd(backend, safe_flags);
    // Linux `open(tty, !O_NOCTTY)` on a session leader with no existing
    // ctty acquires the tty as the session's controlling terminal. Every
    // legacy /dev/* path points at the same console tty until multi-tty
    // support lands (#374).
    if rc >= 0 && (flags as u32) & oflags::O_NOCTTY == 0 {
        let caller = crate::process::current_pid();
        let tty = crate::tty::console_tty();
        let _ = crate::tty::acquire_ctty_on_open(caller, &tty);
    }
    Some(rc)
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

    // 7a. FIFO detour: on an `InodeKind::Fifo`, `open(2)` rendezvous
    //     semantics (POSIX §open) take over. The fd gets a
    //     `FifoOpenBackend` that wraps the pipe end(s) alongside an
    //     `Arc<OpenFile>` — the latter pins the inode + SB (via a
    //     transferred `SbActiveGuard`) and lets fd-keyed inode syscalls
    //     (`fstat` etc.) route through `as_vfs`.
    if inode.kind == InodeKind::Fifo {
        let pipe = match inode.ops.fifo_pipe() {
            Some(p) => p,
            // A FIFO inode must always carry a pipe — surface the bug
            // as ENXIO (same errno used for a write-side rendezvous
            // failure) rather than panic.
            None => return crate::fs::ENXIO,
        };
        let nonblocking = flags32 & oflags::O_NONBLOCK != 0;
        let access = flags32 & oflags::O_ACCMODE;
        // Acquire the pipe end(s) first — O_WRONLY-without-reader
        // returns ENXIO here, and we do not want to have acquired an
        // SbActiveGuard only to immediately drop it on that failure.
        let (read_end, write_end) = match access {
            oflags::O_RDONLY => match pipe.open_read(nonblocking) {
                Ok(r) => (Some(r), None),
                Err(e) => return e,
            },
            oflags::O_WRONLY => match pipe.open_write(nonblocking) {
                Ok(w) => (None, Some(w)),
                Err(e) => return e,
            },
            oflags::O_RDWR => {
                // Linux extension: `O_RDWR` on a FIFO always succeeds.
                // Both ends hang off the same `Arc<Pipe>`, so a write
                // through the fd is observable on a later read.
                let (r, w) = pipe.open_rdwr(nonblocking);
                (Some(r), Some(w))
            }
            _ => return EINVAL,
        };
        // Pin the inode + superblock for the fd's lifetime by building
        // an `OpenFile` around them, the same dance every other
        // path-opened fd goes through (see step 7 below). `OpenFile`'s
        // `Drop` releases the `sb_active` pin.
        let sb = match inode.sb.upgrade() {
            Some(s) => s,
            None => return ENOENT,
        };
        let guard = match SbActiveGuard::try_acquire(&sb) {
            Ok(g) => g,
            Err(e) => return e,
        };
        let of = OpenFile::new(
            nd.path.dentry.clone(),
            inode.clone(),
            inode.file_ops.clone(),
            sb.clone(),
            flags as u32,
            guard,
        );
        let backend: Arc<dyn FileBackend> = Arc::new(FifoOpenBackend {
            vfs: VfsBackend { open_file: of },
            read_end,
            write_end,
        });
        return install_fd(backend, flags as u32);
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

/// FileBackend for a path-opened FIFO fd.
///
/// Holds the pipe end(s) matching the open's access mode alongside an
/// inner [`VfsBackend`] over the FIFO's inode. The `VfsBackend` pins
/// the inode + superblock (via the `SbActiveGuard` transferred into
/// its `OpenFile`), and `as_vfs` returns `Some(&self.vfs)` so fd-keyed
/// inode syscalls (`fstat`, `fstatat` with `AT_EMPTY_PATH`, etc.) see
/// the FIFO's inode rather than falling through to `-EINVAL`.
///
/// `read`/`write` bypass the inner `VfsBackend` and route directly to
/// the pipe ends — FIFO I/O is ring-based rendezvous, not an offset-
/// tracked inode body. `read` on a write-only open returns `EBADF`
/// (mirroring `PipeWriteEnd::read`), and vice versa.
struct FifoOpenBackend {
    /// Inner VFS backend — purely for `as_vfs`/SB pinning. Its `read`/
    /// `write` are never called through this outer backend.
    vfs: VfsBackend,
    read_end: Option<Arc<crate::ipc::pipe::PipeReadEnd>>,
    write_end: Option<Arc<crate::ipc::pipe::PipeWriteEnd>>,
}

impl FileBackend for FifoOpenBackend {
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        match self.read_end.as_ref() {
            Some(r) => r.read(buf),
            None => Err(EBADF),
        }
    }
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        match self.write_end.as_ref() {
            Some(w) => w.write(buf),
            None => Err(EBADF),
        }
    }
    fn poll(&self, pt: &mut crate::poll::PollTable) -> crate::poll::PollMask {
        let mut mask: crate::poll::PollMask = 0;
        if let Some(r) = self.read_end.as_ref() {
            mask |= r.poll(pt);
        }
        if let Some(w) = self.write_end.as_ref() {
            mask |= w.poll(pt);
        }
        mask
    }
    fn set_flags(&self, new_flags: u32) {
        if let Some(r) = self.read_end.as_ref() {
            r.set_flags(new_flags);
        }
        if let Some(w) = self.write_end.as_ref() {
            w.set_flags(new_flags);
        }
    }
    fn as_vfs(&self) -> Option<&VfsBackend> {
        Some(&self.vfs)
    }
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

/// POSIX file-type bits (mask: `S_IFMT`). Only the values we act on are
/// spelled out — the full Linux set is larger, but `mknod` in this
/// kernel only accepts FIFO and regular files today.
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFIFO: u32 = 0o010_000;

/// Shared body for `mknod(2)` / `mknodat(2)`.
///
/// Resolves the parent directory, splits off the leaf name, then dispatches
/// to `InodeOps::mkfifo` (for `S_IFIFO`) or `InodeOps::create` (for
/// `S_IFREG`). Any other type — character/block/socket nodes — returns
/// `-EPERM` since this kernel has no devtmpfs or unix-socket support yet.
fn mknod_impl(dfd: i32, path_uva: u64, mode: u32, _dev: u64) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    // mknod never names a directory — a trailing slash on the leaf is
    // invalid. split_parent strips it silently, so the check has to
    // happen here.
    if path.len() > 1 && path.last() == Some(&b'/') {
        return ENOTDIR;
    }

    // Refuse if the target already exists. Matches Linux mknod semantics
    // (EEXIST on pre-existing path).
    if resolve_inode(path, /* follow */ false).is_ok() {
        return EEXIST;
    }

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

    let perm = (mode & 0o7777) as u16;
    let typ = mode & S_IFMT;
    // A zero type field means "regular file" per POSIX.
    let typ = if typ == 0 { S_IFREG } else { typ };

    match typ {
        S_IFIFO => match parent_inode.ops.mkfifo(&parent_inode, leaf, perm) {
            Ok(_) => 0,
            Err(e) => e,
        },
        S_IFREG => match parent_inode.ops.create(&parent_inode, leaf, perm) {
            Ok(_) => 0,
            Err(e) => e,
        },
        _ => crate::fs::EPERM,
    }
}

/// `mknod(path, mode, dev)` — create a FIFO or regular file at `path`.
pub unsafe fn sys_mknod_impl(path_uva: u64, mode: u64, dev: u64) -> i64 {
    mknod_impl(AT_FDCWD, path_uva, mode as u32, dev)
}

/// `mknodat(dfd, path, mode, dev)` — like `mknod` but relative to `dfd`.
/// Only `AT_FDCWD` and absolute paths are honored today.
pub unsafe fn sys_mknodat_impl(dfd: i32, path_uva: u64, mode: u64, dev: u64) -> i64 {
    mknod_impl(dfd, path_uva, mode as u32, dev)
}

/// Shared body for `mkdir(2)` / `mkdirat(2)`.
///
/// Resolves the parent directory, checks the caller holds `W|X` on it,
/// then dispatches to [`crate::fs::vfs::ops::InodeOps::mkdir`]. Errors
/// are surfaced per RFC 0004 §Kernel-Userspace Interface:
///
/// - `EEXIST` — final component already exists.
/// - `ENOTDIR` — a non-terminal path component is not a directory, or
///   the final component has a trailing slash and the parent isn't one.
/// - `ENOENT` — a path component doesn't exist.
/// - `EACCES` — caller lacks `W|X` on the parent directory.
/// - `ENAMETOOLONG` — path or a component exceeds POSIX caps.
///
/// `ENOTEMPTY` and `EBUSY` are emitted by sibling write-syscalls
/// (rmdir / unlink) that operate on populated / pinned directories;
/// they are mentioned in the errno table for completeness of the
/// POSIX mkdir(2) + rmdir(2) surface but do not arise from mkdir
/// itself.
///
/// Per-process umask application is deferred: this kernel has no
/// umask field on the task struct yet (tracked as a follow-up to
/// RFC 0004 Workstream B). The mode is therefore passed through
/// after masking off non-permission bits (`& 0o7777`), matching
/// how `mknod_impl` handles `mode` today. When umask plumbing lands,
/// the masked mode becomes `mode & ~umask & 0o7777` — a mechanical
/// one-line change here.
fn mkdir_impl(dfd: i32, path_uva: u64, mode: u32) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    // Per-process cwd / fd-rooted walks don't exist yet — accept only
    // AT_FDCWD for relative paths (same precondition as openat/mknodat).
    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    // `split_parent` strips a trailing slash from the leaf. Directories
    // are the one kind of thing where a trailing slash on the path is
    // legitimate — `mkdir("/foo/")` is the same as `mkdir("/foo")` per
    // POSIX — so no equivalent of `mknod_impl`'s trailing-slash rejection
    // is needed here.

    // Normalize the leaf first so that invalid leaves (".", "..", "") are
    // rejected with ENOENT (per the PR contract) before any EEXIST fast
    // path gets a chance to classify them. Running `resolve_inode` first
    // would let `/tmp/.` map to the existing `/tmp` inode and return
    // EEXIST, which is the wrong errno.
    let (parent_path, leaf) = match split_parent(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Refuse if the target already exists. The pre-check races with a
    // concurrent creator, but the authoritative check is the FS driver's
    // own duplicate-insert path — RamFs returns EEXIST under the dir
    // rwsem (see `ramfs::InodeOps::mkdir`). The pre-walk just avoids
    // the more expensive permission-check + parent-resolution round-trip
    // when we already know the answer.
    if resolve_inode(path, /* follow */ false).is_ok() {
        return EEXIST;
    }
    let (parent_inode, _pnd) = match resolve_inode(parent_path, /* follow */ true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if parent_inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // DAC check: POSIX `mkdir(2)` requires write + search (execute bit
    // on a directory) on the parent. Goes through `InodeOps::permission`
    // so ACL-style overrides can take effect once an FS driver implements
    // them. Until Workstream B plumbs per-task credentials, the caller
    // is always `Credential::kernel()` (root) — the dispatch arm is
    // feature-gated so this placeholder is never reachable from ring-3.
    let cred = Credential::kernel();
    let access = Access::WRITE | Access::EXECUTE;
    if let Err(e) = parent_inode.ops.permission(&parent_inode, &cred, access) {
        return e;
    }

    // Strip non-permission bits from `mode` (caller may have spuriously
    // OR'd in S_IF* constants per some libc idioms). The driver is
    // responsible for setting the `S_IFDIR` type bit on the new inode.
    let perm = (mode & 0o7777) as u16;
    match parent_inode.ops.mkdir(&parent_inode, leaf, perm) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// `mkdir(path, mode)` — create a directory at `path`.
///
/// Dispatches through [`mkdir_impl`] with `dfd = AT_FDCWD`.
pub unsafe fn sys_mkdir_impl(path_uva: u64, mode: u64) -> i64 {
    mkdir_impl(AT_FDCWD, path_uva, mode as u32)
}

/// `mkdirat(dfd, path, mode)` — like `mkdir` but relative to `dfd`.
///
/// Honors `AT_FDCWD` (use the current working directory) and absolute
/// paths; a real fd with a relative path returns `EINVAL` until
/// per-process fd-rooted walks land (issue #239).
pub unsafe fn sys_mkdirat_impl(dfd: i32, path_uva: u64, mode: u64) -> i64 {
    mkdir_impl(dfd, path_uva, mode as u32)
}

/// `rmdir(path)` — remove an empty directory.
///
/// RFC 0004 — Workstream A: wires the syscall to
/// [`crate::fs::vfs::ops::InodeOps::rmdir`] on the parent directory's
/// inode. The trait implementation is responsible for verifying the
/// target is a directory, that it is empty (non-empty → `-ENOTEMPTY`),
/// taking `dir_rwsem` for the parent, and decrementing the parent's
/// `nlink` for the removed `..` backlink.
///
/// Shaping done here (POSIX deltas that the per-FS op can't see):
/// - Empty path → `-ENOENT`.
/// - Bare `/` → `-EBUSY` (removing the mount root is always refused).
/// - Leaf of `.` (e.g. `rmdir(".")` or `rmdir("foo/.")`) → `-EINVAL`.
/// - Leaf of `..` (e.g. `rmdir("..")` or `rmdir("foo/..")`) →
///   `-ENOTEMPTY`, matching Linux. Kept separate from `.` so callers
///   can tell "current directory" from "parent of".
/// - Parent not a directory → `-ENOTDIR`.
///
/// Credential is `Credential::kernel()` until Workstream B (#546)
/// lands per-task credentials.
pub unsafe fn sys_rmdir_impl(path_uva: u64) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    if path.is_empty() {
        return ENOENT;
    }

    // Collapse *all* trailing slashes so "/foo", "/foo/", and "/foo//"
    // share the leaf check and the parent split. Bare "/" survives as
    // "/" because the loop only strips while `len > 1`.
    let mut trimmed: &[u8] = path;
    while trimmed.len() > 1 && *trimmed.last().unwrap() == b'/' {
        trimmed = &trimmed[..trimmed.len() - 1];
    }

    // `rmdir("/")` never succeeds — the FS root is a mountpoint that
    // cannot be removed. Return EBUSY per Linux's root-removal errno.
    if trimmed == b"/" {
        return crate::fs::EBUSY;
    }

    // Locate the leaf to enforce POSIX's `.` / `..` rejection before
    // committing to a full path walk. The resolver below would
    // otherwise resolve `.` / `..` silently and mis-target an ancestor.
    let leaf_after_slash = trimmed
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| &trimmed[i + 1..])
        .unwrap_or(trimmed);
    if leaf_after_slash == b"." {
        // POSIX: rmdir(".") is always EINVAL.
        return EINVAL;
    }
    if leaf_after_slash == b".." {
        // Linux: rmdir("..") returns ENOTEMPTY because the parent
        // directory has `.` and children referring back.
        return crate::fs::ENOTEMPTY;
    }

    // Pass the trailing-slash-collapsed path to `split_parent` so the
    // inner strip logic sees a clean leaf (it only peels one slash
    // itself, so multi-slash inputs would otherwise come back with an
    // empty leaf → ENOENT).
    let (parent_path, leaf) = match split_parent(trimmed) {
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

    match parent_inode.ops.rmdir(&parent_inode, leaf) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Shared body for `unlink(2)` / `unlinkat(2)`.
///
/// Resolves the parent directory, splits off the leaf name, then
/// dispatches to `InodeOps::unlink` (default) or `InodeOps::rmdir`
/// (when `AT_REMOVEDIR` is set in `flags`). Enforces the common POSIX
/// pre-checks the trait impls must not each reinvent:
///
/// - Trailing-slash leaf forces directory semantics: non-`AT_REMOVEDIR`
///   `unlink("foo/")` returns `EISDIR` since the caller named a
///   directory explicitly.
/// - A `.` / `..` / empty leaf is rejected upfront via `split_parent`.
/// - The leaf may not itself be a mountpoint — `EBUSY` per POSIX
///   (rmdir/unlink on a mount root is always refused).
/// - Sticky-bit (`S_ISVTX`) on the parent directory forces the caller
///   to own the parent or the target file; root bypasses.
///
/// The body is always compiled — only the syscall *dispatch arms*
/// upstream are gated behind `#[cfg(feature = "vfs_creds")]`. Tests
/// reach this impl directly through `sys_unlink_impl` /
/// `sys_unlinkat_impl`, mirroring the convention `sys_mkdir_impl`
/// established in #585. Until Workstream B flips `vfs_creds` on,
/// ring-3 callers see `-ENOSYS` because the dispatcher's default
/// arm catches the syscall numbers.
fn unlinkat_impl(dfd: i32, path_uva: u64, flags: u32) -> i64 {
    // Only AT_REMOVEDIR is recognised today. Everything else must be
    // whitelisted explicitly so a silent-accept never masks a future
    // flag bit.
    if flags & !AT_REMOVEDIR != 0 {
        return EINVAL;
    }
    let remove_dir = flags & AT_REMOVEDIR != 0;

    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    // `*at` preconditions mirror `openat`: non-AT_FDCWD dfd with a
    // relative path is out of scope until per-fd cwd lands (#239).
    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    // Trailing-slash means the caller explicitly named a directory.
    // POSIX unlink(2) on a trailing-slash path returns EISDIR (or
    // ENOTDIR if the final component does not resolve to a directory);
    // Linux picks EISDIR when the named leaf itself is a directory and
    // we mirror that here. `rmdir`/`AT_REMOVEDIR` accepts a trailing
    // slash since that's the POSIX-preferred spelling for directories.
    let trailing_slash = path.len() > 1 && path.last() == Some(&b'/');

    let (parent_path, leaf) = match split_parent(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Resolve the parent (follow symlinks on every intermediate
    // component — standard POSIX behaviour).
    let (parent_inode, pnd) = match resolve_inode(parent_path, /* follow */ true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if parent_inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // Resolve the leaf via lookup on the parent so we can run the
    // mountpoint + sticky checks before calling into the FS driver.
    // We intentionally do NOT go back through `path_walk` for the
    // leaf — that would cross a symlink on a symlinked leaf and delete
    // the wrong thing. `unlink`/`rmdir` always act on the name itself.
    let leaf_inode = match parent_inode.ops.lookup(&parent_inode, leaf) {
        Ok(i) => i,
        Err(e) => return e,
    };

    // Mountpoint check: we need the leaf's dentry to inspect `.mount`.
    // `pnd.path.dentry` is the parent-directory dentry after the walk.
    // Look the leaf up in the parent's child cache — if a mount edge
    // is attached to the leaf dentry, refuse with `EBUSY` per POSIX.
    // A miss in the child cache (or a negative entry) means nothing
    // is mounted on the leaf, so there is no mountpoint to refuse.
    if let Ok(leaf_dstr) = crate::fs::vfs::DString::try_from_bytes(leaf) {
        let parent_dentry = pnd.path.dentry.clone();
        let children = parent_dentry.children.read();
        if let Some(crate::fs::vfs::ChildState::Resolved(child)) = children.get(&leaf_dstr) {
            if child.mount.read().is_some() {
                return EBUSY;
            }
        }
    }

    // Kind-based dispatch. `unlink` on a directory is EISDIR; `rmdir`
    // on a non-directory is ENOTDIR. Drivers can still reject on their
    // own, but catching it up front gives a consistent errno across
    // backends.
    if remove_dir {
        if leaf_inode.kind != InodeKind::Dir {
            return ENOTDIR;
        }
    } else {
        if leaf_inode.kind == InodeKind::Dir {
            return EISDIR;
        }
        if trailing_slash {
            // unlink("foo/") where foo is a symlink to a directory is
            // still refused (ENOTDIR on Linux). Here the leaf isn't a
            // directory but the caller named a directory explicitly,
            // so ENOTDIR best describes the mismatch. Unreachable for
            // regular files via split_parent today, but kept as a
            // defensive guard for future resolver behaviour.
            return ENOTDIR;
        }
    }

    // Sticky-bit check. When S_ISVTX is set on the parent, POSIX
    // requires the caller to own either the parent or the target
    // file, or be the super-user. Uses `Credential::kernel()` as a
    // placeholder — replaced by the per-task credential when
    // Workstream B flips `vfs_creds` on (#546).
    let cred = Credential::kernel();
    let parent_meta = parent_inode.meta.read();
    if parent_meta.mode & S_ISVTX != 0 && cred.uid != 0 {
        let leaf_uid = leaf_inode.meta.read().uid;
        if cred.uid != parent_meta.uid && cred.uid != leaf_uid {
            return EPERM;
        }
    }
    drop(parent_meta);

    let r = if remove_dir {
        parent_inode.ops.rmdir(&parent_inode, leaf)
    } else {
        parent_inode.ops.unlink(&parent_inode, leaf)
    };
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `unlink(path)` — remove a non-directory from its parent. Thin
/// wrapper over [`unlinkat_impl`] with `dfd = AT_FDCWD` and no flags.
///
/// Reachable from ring-3 only when the `vfs_creds` feature is on
/// (the dispatch arm is gated). Tests call this entry point directly
/// to exercise the impl regardless of feature state, mirroring the
/// `sys_mkdir_impl` convention from #585.
pub unsafe fn sys_unlink_impl(path_uva: u64) -> i64 {
    unlinkat_impl(AT_FDCWD, path_uva, 0)
}

/// `unlinkat(dfd, path, flags)` — `unlink` or `rmdir` (when `flags`
/// sets `AT_REMOVEDIR`) relative to `dfd`. `AT_FDCWD` and absolute
/// paths only; a real fd with a relative path returns `EINVAL` until
/// per-fd cwd semantics land (#239).
///
/// Reachable from ring-3 only when `vfs_creds` is on (gated dispatch
/// arm). See [`sys_unlink_impl`] for the test-path convention.
pub unsafe fn sys_unlinkat_impl(dfd: i32, path_uva: u64, flags: u32) -> i64 {
    unlinkat_impl(dfd, path_uva, flags)
}

// ---------------------------------------------------------------------------
// chmod / fchmod / fchmodat + chown / fchown / fchownat / lchown (issue #541)
//
// Wires the POSIX metadata-mutation syscalls to `InodeOps::setattr`. The
// permission model lives here rather than in the per-FS driver so every
// backend (RamFs, TarFs, ext2 when it lands) inherits the same rules —
// drivers only decide how to persist the requested mutation.
//
// Rules (RFC 0004 §Permission model, POSIX.1-2017 §chmod/§chown):
//   - `chmod`: only the file's owner (`euid == meta.uid`) or root
//     (`euid == 0`) may change mode. Anyone else gets `-EPERM`.
//   - `chown`: only root may change `uid`. The owner may change `gid`
//     but only to a group they are a member of (`egid` or
//     `supplementary groups`). Anyone else gets `-EPERM`.
//   - `fchown(fd, -1, -1)` (no-op) returns 0.
//   - `chown` on a regular file by a non-root caller *clears*
//     `S_ISUID` / `S_ISGID` (when exec-group is set) on success, per
//     POSIX and Linux. Root-initiated chown preserves the bits.
//   - `fchmodat(AT_SYMLINK_NOFOLLOW)` is unsupported on Linux for the
//     mode mutation; we accept the flag and ignore it (chmod always
//     follows the symlink) to match Linux's de-facto behaviour.
//   - `fchownat(AT_SYMLINK_NOFOLLOW)` operates on the symlink itself —
//     this is the primitive `lchown` is built on.
// ---------------------------------------------------------------------------

/// `S_ISUID` — set-user-ID bit on a file's mode word. Cleared on a
/// non-root `chown` per POSIX.
const S_ISUID: u16 = 0o4000;
/// `S_ISGID` — set-group-ID bit on a file's mode word. Cleared on a
/// non-root `chown` **only** when the group-exec bit is set (the usual
/// idiom: `S_ISGID` without `S_IXGRP` signals mandatory locking on
/// Linux, not a setgid binary, and must be preserved).
const S_ISGID: u16 = 0o2000;
/// `S_IXGRP` — group-execute bit. Used alongside `S_ISGID` to
/// distinguish a setgid binary (`S_ISGID | S_IXGRP`) from a mandatory-
/// locking marker (`S_ISGID` alone).
const S_IXGRP: u16 = 0o0010;

/// Shared chmod body. Applies `mode & 0o7777` to `inode`'s metadata
/// via `InodeOps::setattr`, after checking the caller owns the file
/// or is root.
///
/// `inode` is the resolved target (post-path-walk for path-based
/// callers, post-fd-lookup for `fchmod`). `cred` is the caller's
/// per-task credential snapshot.
fn do_chmod(inode: &Arc<Inode>, mode: u16, cred: &Credential) -> i64 {
    // Ownership gate. POSIX: only the owner or a process with
    // appropriate privileges (root) may change mode.
    let owner_uid = inode.meta.read().uid;
    if cred.euid != 0 && cred.euid != owner_uid {
        return EPERM;
    }
    let attr = SetAttr {
        mask: SetAttrMask::MODE,
        mode: mode & 0o7777,
        ..SetAttr::default()
    };
    match inode.ops.setattr(inode, &attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Shared chown body. Applies `uid` / `gid` changes (when they are not
/// the "don't change" sentinel `u32::MAX`, matching the C `-1` cast)
/// via `InodeOps::setattr`, enforcing POSIX's narrow ownership /
/// group-membership rules.
///
/// Clears the set-user-ID bit (and the set-group-ID bit when group-exec
/// is set) on a regular file whenever the chown is performed by a
/// non-root caller — POSIX §chown. A root-initiated chown preserves
/// the bits.
fn do_chown(inode: &Arc<Inode>, uid: u32, gid: u32, cred: &Credential) -> i64 {
    // Linux / POSIX: -1 (interpreted as u32::MAX) means "don't change".
    let change_uid = uid != u32::MAX;
    let change_gid = gid != u32::MAX;
    if !change_uid && !change_gid {
        // Nothing to do. Per POSIX fchown(2) §Application Usage: this
        // is a success no-op (matches `fchown(fd, -1, -1)`).
        return 0;
    }

    let (cur_uid, cur_gid, cur_mode) = {
        let meta = inode.meta.read();
        (meta.uid, meta.gid, meta.mode)
    };

    // uid-side rules.
    if change_uid {
        // Only root may change the owning uid. An owner is not allowed
        // to "give away" their file to another user.
        if cred.euid != 0 {
            return EPERM;
        }
    }

    // gid-side rules.
    if change_gid {
        if cred.euid != 0 {
            // Non-root: must own the file AND the target gid must be
            // in the caller's group set (egid or supplementary).
            if cred.euid != cur_uid {
                return EPERM;
            }
            let in_group = cred.egid == gid || cred.groups.iter().any(|&g| g == gid);
            if !in_group {
                return EPERM;
            }
        }
    }

    // Compute the post-chown mode. POSIX: a successful chown by a
    // non-root caller clears S_ISUID and (conditionally) S_ISGID on
    // a regular file. The S_ISGID-without-S_IXGRP case is the
    // mandatory-locking marker on Linux and must be preserved.
    let mut new_mode = cur_mode;
    let mut clear_setid = false;
    if inode.kind == InodeKind::Reg && cred.euid != 0 {
        if new_mode & S_ISUID != 0 {
            new_mode &= !S_ISUID;
            clear_setid = true;
        }
        if new_mode & S_ISGID != 0 && new_mode & S_IXGRP != 0 {
            new_mode &= !S_ISGID;
            clear_setid = true;
        }
    }

    let mut mask = SetAttrMask::default();
    if change_uid {
        mask = mask | SetAttrMask::UID;
    }
    if change_gid {
        mask = mask | SetAttrMask::GID;
    }
    if clear_setid {
        mask = mask | SetAttrMask::MODE;
    }
    let attr = SetAttr {
        mask,
        mode: new_mode,
        uid: if change_uid { uid } else { cur_uid },
        gid: if change_gid { gid } else { cur_gid },
        ..SetAttr::default()
    };
    match inode.ops.setattr(inode, &attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Resolve the inode behind an fd for the fchmod/fchown family. Returns
/// `EBADF` on an out-of-range fd, or on any backend that doesn't expose
/// a VFS inode (e.g. a pure `SerialBackend`) since there is nothing to
/// mutate there.
fn fd_to_inode(fd_raw: u64) -> Result<Arc<Inode>, i64> {
    if fd_raw > u32::MAX as u64 {
        return Err(EBADF);
    }
    let fd = fd_raw as u32;
    let tbl = crate::task::current_fd_table();
    let backend = tbl.lock().get(fd).map_err(|_| EBADF)?;
    match backend.as_vfs() {
        Some(v) => Ok(v.open_file.inode.clone()),
        None => Err(EBADF),
    }
}

/// Shared path-mode chmod body. Used by `sys_chmod_impl` and
/// `sys_fchmodat_impl`; `dfd` is honored only for `AT_FDCWD` /
/// absolute paths until per-fd walks land (#239).
fn chmodat_impl(dfd: i32, path_uva: u64, mode: u32, flags: u32) -> i64 {
    // Only `AT_SYMLINK_NOFOLLOW` is a recognised flag for fchmodat on
    // Linux, and even there it is not supported — Linux returns
    // `EOPNOTSUPP`. We mirror Linux's de-facto behaviour: accept the
    // flag bit, but the trailing-symlink semantics are always "follow"
    // (`chmod` on a symlink chases it). Any other bit is rejected so
    // future additions are whitelisted explicitly.
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return EINVAL;
    }
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    let cred = crate::task::current_credentials();
    // chmod always resolves through a trailing symlink — the target
    // file is what gets its mode updated. `AT_SYMLINK_NOFOLLOW` on
    // Linux returns EOPNOTSUPP; we accept-and-ignore it for simplicity
    // since the only sensible answer on an in-memory symlink is to
    // follow (there's nothing on a symlink inode to chmod).
    let (inode, _nd) = match resolve_inode_as(path, /* follow */ true, (*cred).clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_chmod(&inode, mode as u16, &cred)
}

/// `chmod(path, mode)` — change the mode bits of `path`.
pub unsafe fn sys_chmod_impl(path_uva: u64, mode: u64) -> i64 {
    chmodat_impl(AT_FDCWD, path_uva, mode as u32, 0)
}

/// `fchmod(fd, mode)` — change the mode bits of the file behind an
/// already-open fd.
pub unsafe fn sys_fchmod_impl(fd_raw: u64, mode: u64) -> i64 {
    let inode = match fd_to_inode(fd_raw) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let cred = crate::task::current_credentials();
    do_chmod(&inode, mode as u16, &cred)
}

/// `fchmodat(dfd, path, mode, flags)` — `*at` form of chmod.
pub unsafe fn sys_fchmodat_impl(dfd: i32, path_uva: u64, mode: u64, flags: u32) -> i64 {
    chmodat_impl(dfd, path_uva, mode as u32, flags)
}

/// Shared path-mode chown body. Used by `sys_chown_impl`, `sys_lchown_impl`,
/// and `sys_fchownat_impl`. `follow` controls whether a terminal
/// symlink is chased (chown vs lchown).
fn chownat_impl(dfd: i32, path_uva: u64, uid: u32, gid: u32, flags: u32) -> i64 {
    // `fchownat` only recognises `AT_SYMLINK_NOFOLLOW` today. Future
    // additions like `AT_EMPTY_PATH` need to be whitelisted explicitly.
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return EINVAL;
    }
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let is_absolute = path.first() == Some(&b'/');
    if dfd != AT_FDCWD && !is_absolute {
        return EINVAL;
    }

    let cred = crate::task::current_credentials();
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (inode, _nd) = match resolve_inode_as(path, follow, (*cred).clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_chown(&inode, uid, gid, &cred)
}

/// `chown(path, uid, gid)` — change owner/group; follows symlinks.
pub unsafe fn sys_chown_impl(path_uva: u64, uid: u64, gid: u64) -> i64 {
    chownat_impl(AT_FDCWD, path_uva, uid as u32, gid as u32, 0)
}

/// `fchown(fd, uid, gid)` — change owner/group of an open fd's file.
pub unsafe fn sys_fchown_impl(fd_raw: u64, uid: u64, gid: u64) -> i64 {
    let inode = match fd_to_inode(fd_raw) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let cred = crate::task::current_credentials();
    do_chown(&inode, uid as u32, gid as u32, &cred)
}

/// `lchown(path, uid, gid)` — change owner/group; does **not** follow a
/// terminal symlink. Equivalent to
/// `fchownat(AT_FDCWD, path, uid, gid, AT_SYMLINK_NOFOLLOW)`.
pub unsafe fn sys_lchown_impl(path_uva: u64, uid: u64, gid: u64) -> i64 {
    chownat_impl(
        AT_FDCWD,
        path_uva,
        uid as u32,
        gid as u32,
        AT_SYMLINK_NOFOLLOW,
    )
}

/// `fchownat(dfd, path, uid, gid, flags)` — `*at` form of chown.
pub unsafe fn sys_fchownat_impl(dfd: i32, path_uva: u64, uid: u64, gid: u64, flags: u32) -> i64 {
    chownat_impl(dfd, path_uva, uid as u32, gid as u32, flags)
}
